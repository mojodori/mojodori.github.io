# 🔐 VMware 기반 보안 홈랩 구축

> **Suricata IDS · ELK SIEM · DVWA 모의해킹 · macOS M2 + VMware Fusion 13**

클라우드 인프라를 공부하며 보안의 필요성을 직접 체감한 것이 출발점이었습니다.  
인프라를 설계할 줄 알기 때문에, 그 위에 보안 레이어가 어떻게 쌓여야 하는지 이해하며 직접 구현했습니다.

---

## 📊 핵심 결과

| 항목 | 결과 |
|------|------|
| 구성 VM | 9대 |
| Suricata 탐지 건수 | **2,031건** |
| MariaDB 적재 건수 | **2,031건** (100% 일치) |
| Elasticsearch 인덱스 | **2,031건** (100% 일치) |
| 작업 기간 | 2026.06.28 ~ 06.29 |

---

## 🖥️ 환경

| 항목 | 내용 |
|------|------|
| 호스트 | macOS M2 · VMware Fusion 13 |
| 게스트 OS | Ubuntu 20.04.5 LTS ARM64 |
| 네트워크 | NAT 172.16.60.0/24 |

---

## 🗺️ 네트워크 구성

```
[macOS M2 호스트]
       │ Bridged SSH
       ▼
[Bastion Host]  192.168.0.30  ← 외부 유일 진입점
       │
       │ NAT 172.16.60.0/24
       ├─── [OpenVPN]   172.16.60.131  VPN 서버
       ├─── [WEB/Nginx] 172.16.60.132  리버스 프록시 + HTTPS
       │         │ proxy_pass
       │         ▼
       │    [WAS/DVWA]  172.16.60.134  Apache + DVWA
       │         │ 3306
       │         ▼
       │    [MariaDB]   172.16.60.133  DB (계정 권한 분리)
       │
       ├─── [Suricata]  172.16.60.135  IDS (소스 컴파일 6.0.13)
       │         │ eve.json → Filebeat
       │         ▼
       ├─── [ELK SIEM]  172.16.60.136  Elasticsearch + Logstash + Kibana
       │
       ├─── [Kali]      172.16.60.138  모의해킹 (nmap · nikto · SQLi · XSS)
       └─── [Portfolio] 172.16.60.140  Nginx 정적 서버
```

---

## 🔒 보안 설계 원칙

### 1. 단일 진입점 (Bastion Host)
외부에 노출되는 지점을 9개 → 1개로 축소. 공격 표면 최소화(Attack Surface Reduction).

### 2. 최소 권한 원칙 (DB 계정 분리)
- `wasuser` → `homelab_db` 전체 권한 (WAS 전용)
- `logstash` → `alerts` 테이블 INSERT만 (SIEM 전용)
- SIEM이 침해당해도 기존 alert 조회·삭제 불가 → 피해 범위 한정

### 3. 화이트리스트 방화벽 (Default Deny)
`ufw allow 3306` 처럼 포트만 여는 게 아니라 `from <IP>` 로 출발지까지 제한.

### 4. 리버스 프록시 (WEB/WAS 분리)
WAS 실제 IP를 외부에 노출하지 않음. HTTPS·보안헤더를 WEB 단에서 일괄 처리.

### 5. 데이터 이중 저장 (MariaDB + Elasticsearch)
- MariaDB → 정형 쿼리·장기 보관 (SQL 기반 분석)
- Elasticsearch → 전문 검색·Kibana 시각화

---

## 📁 파일 구조

```
homelab-security/
├── README.md
├── configs/
│   ├── suricata.yaml        # Suricata IDS 핵심 설정
│   ├── filebeat.yml         # 로그 수집 설정
│   ├── logstash.conf        # 파이프라인 필터 (파싱 + 이중 출력)
│   └── nginx.conf           # 리버스 프록시 + 보안 헤더
├── firewall/
│   └── ufw-rules.sh         # UFW 화이트리스트 설정 스크립트
└── sql/
    └── init.sql             # DB 스키마 + 계정 권한 설정
```

---

## ⚙️ 설정 파일

### Suricata 핵심 설정 (`configs/suricata.yaml`)

```yaml
vars:
  address-groups:
    HOME_NET: "[172.16.60.0/24]"
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: ens160
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: yes
            packet: yes
        - http
        - dns
        - tls
```

### Filebeat 설정 (`configs/filebeat.yml`)

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/suricata/eve.json
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      source: suricata
    fields_under_root: true

output.logstash:
  hosts: ["172.16.60.136:5044"]
```

### Logstash 파이프라인 (`configs/logstash.conf`)

```ruby
input {
  beats {
    port => 5044
  }
}

filter {
  # alert 이벤트만 처리
  if [event_type] != "alert" {
    drop {}
  }

  # 심각도 분류
  if [alert][severity] == 1 {
    mutate { add_field => { "severity_label" => "HIGH" } }
  } else if [alert][severity] == 2 {
    mutate { add_field => { "severity_label" => "MEDIUM" } }
  } else {
    mutate { add_field => { "severity_label" => "LOW" } }
  }

  mutate {
    add_field => { "[@metadata][index]" => "suricata-%{+YYYY.MM.dd}" }
  }
}

output {
  # Elasticsearch 적재
  elasticsearch {
    hosts => ["http://172.16.60.136:9200"]
    index => "%{[@metadata][index]}"
  }

  # MariaDB 동시 적재 (JDBC)
  jdbc {
    driver_jar_path => "/usr/share/logstash/vendor/mariadb-java-client.jar"
    driver_class => "org.mariadb.jdbc.Driver"
    connection_string => "jdbc:mariadb://172.16.60.133:3306/homelab_db"
    username => "logstash"
    password => "LogstashPass!"
    statement => [
      "INSERT INTO alerts (timestamp, src_ip, dest_ip, proto, alert_signature, severity)
       VALUES (?, ?, ?, ?, ?, ?)",
      "%{@timestamp}", "%{src_ip}", "%{dest_ip}", "%{proto}",
      "%{[alert][signature]}", "%{[alert][severity]}"
    ]
  }
}
```

### Nginx 리버스 프록시 + 보안 헤더 (`configs/nginx.conf`)

```nginx
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     /etc/ssl/certs/homelab.crt;
    ssl_certificate_key /etc/ssl/private/homelab.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # 보안 헤더
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://172.16.60.134:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

---

## 🔥 방화벽 설정 (`firewall/ufw-rules.sh`)

```bash
#!/bin/bash
# UFW 화이트리스트 방화벽 설정
# 포트만 여는 게 아니라 from <IP>로 출발지까지 제한

# 기본 정책: 전부 차단
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Bastion: SSH만
sudo ufw allow 22/tcp

# WEB: 80/443만
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# DB: WAS와 SIEM에서만 3306 허용
sudo ufw allow from 172.16.60.134 to any port 3306   # WAS
sudo ufw allow from 172.16.60.136 to any port 3306   # SIEM

# SIEM: Filebeat 수신
sudo ufw allow 5044/tcp

sudo ufw enable
sudo ufw status verbose
```

---

## 🗄️ DB 스키마 및 계정 권한 (`sql/init.sql`)

```sql
-- 데이터베이스 생성
CREATE DATABASE homelab_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE homelab_db;

-- alert 적재 테이블
CREATE TABLE alerts (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    timestamp     DATETIME,
    src_ip        VARCHAR(45),
    dest_ip       VARCHAR(45),
    proto         VARCHAR(10),
    alert_signature TEXT,
    severity      INT,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- DVWA 전용 DB
CREATE DATABASE dvwa CHARACTER SET utf8mb4;

-- 계정 분리 (최소 권한 원칙)
-- WAS 전용: homelab_db 전체 권한
CREATE USER 'wasuser'@'172.16.60.134' IDENTIFIED BY 'SecureDBPass!';
GRANT ALL PRIVILEGES ON homelab_db.* TO 'wasuser'@'172.16.60.134';

-- SIEM 전용: alerts 테이블 INSERT만
CREATE USER 'logstash'@'172.16.60.136' IDENTIFIED BY 'LogstashPass!';
GRANT INSERT ON homelab_db.alerts TO 'logstash'@'172.16.60.136';

-- DVWA 전용
CREATE USER 'dvwa'@'172.16.60.134' IDENTIFIED BY 'dvwapass';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'172.16.60.134';

FLUSH PRIVILEGES;
```

---

## 🚨 트러블슈팅

| 문제 | 원인 | 해결 |
|------|------|------|
| Suricata apt 설치 불가 | ARM64 PPA 미지원 | 소스 컴파일 (6.0.13) |
| Logstash → DB 접속 실패 | logstash 계정 호스트 IP 불일치 | SIEM IP 기준 계정 재생성 |
| Kibana EADDRNOTAVAIL | NAT 환경 특정 IP 바인딩 실패 | `server.host: "0.0.0.0"` |
| 룰 로딩 66,733개 지연 | 전체 룰 로드 시간 초과 | SCAN 관련 654개로 최적화 |
| Kali ISO 인식 불가 | macOS quarantine 속성 | `xattr -d com.apple.quarantine` |
| pfSense 설치 불가 | M2 ARM64, x86 전용 | NAT + UFW로 대체 |

---

## 📄 산출물

| 문서 | 내용 |
|------|------|
| [취약점 진단 보고서](docs/취약점_진단_보고서_DVWA.pdf) | DVWA 모의해킹 결과 · 6건 취약점 |
| [보안 아키텍처 설계 보고서](docs/보안_아키텍처_설계_보고서.pdf) | 설계 결정 근거 · 보안 통제 목록 · 잔여 위험 |

---

## 🔭 향후 계획

- [ ] GNS3 + OPNsense(ARM) 기반 VLAN 5단 분리 구현
- [ ] Suricata IPS 모드 전환 (탐지 → 차단)
- [ ] Trivy + Nuclei 취약점 자동 탐지 파이프라인 구축
- [ ] logrotate + ELK ILM 로그 보존 정책 적용

---

## 👩‍💻 작성자

최시은 · 한국폴리텍대학 강서캠퍼스 사이버보안과  
[포트폴리오](https://mojodori.github.io) · [Notion](https://gifted-elderberry-5d6.notion.site/VMware-Fusion-13-Suricata-IDS-ELK-SIEM-DVWA-Kali-Linux-38e30b8e046380af8058f962d6c45528)
