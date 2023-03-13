#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo -e "\n[!] Please run this script with sudo privileges\n"
  exit
fi

echo -e "\n[*] Setting the Datadog Agent..."

# read -p "DataDog API Key : " API_KEY

# DD_API_KEY="$API_KEY" DD_SITE="us5.datadoghq.com" bash -c "$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_script_agent7.sh)"

echo -e "\n[*] Enabling Datadog logs..."

cp /etc/datadog-agent/datadog.yaml.example /etc/datadog-agent/datadog.yaml

echo "logs_enabled: true" >>/etc/datadog-agent/datadog.yaml

echo -e "\n[+] Log Service Enabled..."

# ============== Apache Logs =============

apache_logs() {

  cp /etc/datadog-agent/conf.d/apache.d/conf.yaml.example /etc/datadog-agent/conf.d/apache.d/conf.yaml
  echo "
logs:

    # - type : (mandatory) type of log input source (tcp / udp / file)
    #   port / path : (mandatory) Set port if type is tcp or udp. Set path if type is file
    #   service : (mandatory) name of the service owning the log
    #   source : (mandatory) attribute that defines which integration is sending the log
    #   sourcecategory : (optional) Multiple value attribute. Can be used to refine the source attribute
    #   tags: (optional) add tags to each log collected

  - type: file
    path: /var/log/apache2/access.log
    source: apache
    sourcecategory: http_web_access
    service: myservice

  - type: file
    path: /var/log/apache2/error.log
    source: apache
    sourcecategory: http_web_access
    service: myservice" >>/etc/datadog-agent/conf.d/apache.d/conf.yaml

  chmod 777 /var/log/apache2
  chmod +r /var/log/apache2/*.log
  echo "0 01 * * *    root    chmod +r /var/log/apache2/*.log" >>/etc/crontab

  # echo -e "[*] Apache Logs Enabled...\n"
}

# ============== Nginx Logs =============

nginx_logs() {

  cp /etc/datadog-agent/conf.d/nginx.d/conf.yaml.example /etc/datadog-agent/conf.d/nginx.d/conf.yaml
  echo "
logs:

    # - type : (mandatory) type of log input source (tcp / udp / file)
    #   port / path : (mandatory) Set port if type is tcp or udp. Set path if type is file
    #   service : (mandatory) name of the service owning the log
    #   source : (mandatory) attribute that defines which integration is sending the log
    #   sourcecategory : (optional) Multiple value attribute. Can be used to refine the source attribute
    #   tags: (optional) add tags to each log collected

  - type: file
    service: myservice
    path: /var/log/nginx/access.log
    source: nginx
    sourcecategory: http_web_access

  - type: file
    service: myservice
    path: /var/log/nginx/error.log
    source: nginx
    sourcecategory: http_web_access" >>/etc/datadog-agent/conf.d/nginx.d/conf.yaml

  chmod +r /var/log/nginx/*.log
  echo "0 01 * * *    root    chmod +r /var/log/nginx/*.log" >>/etc/crontab

  # echo -e "[*] Nginx Logs Enabled...\n"
}

# =============== MySql Logs ===============
mysql_logs() {

  mv /etc/mysql/conf.d/mysqld_safe_syslog.cnf /etc/mysql/conf.d/mysqld_safe_syslog.cnf.bak
  touch /etc/mysql/conf.d/mysqld_safe_syslog.cnf

  echo "
[mysqld_safe]
log_error=/var/log/mysql/mysql_error.log

[mysqld]
general_log = on
general_log_file = /var/log/mysql/mysql.log
log_error=/var/log/mysql/mysql_error.log
slow_query_log = on
slow_query_log_file = /var/log/mysql/mysql-slow.log
long_query_time = 2

performance_schema = on
max_digest_length = 4096
performance_schema_max_digest_length = 4096
#performance_schema_max_sql_text_length = 4096
performance-schema-consumer-events-statements-current = on
performance-schema-consumer-events-waits-current = on
performance-schema-consumer-events-statements-history-long = on
performance-schema-consumer-events-statements-history = on
" >>/etc/mysql/my.cnf

  echo -e "
\n[!] Please Execute the following commands in your mysql database to enable the database Performance Tracing\n
CREATE USER datadog@'%' IDENTIFIED BY 'datadog';
GRANT REPLICATION CLIENT ON *.* TO datadog@'%' WITH MAX_USER_CONNECTIONS 5;
GRANT PROCESS ON *.* TO datadog@'%';
GRANT SELECT ON performance_schema.* TO datadog@'%';

CREATE SCHEMA IF NOT EXISTS datadog;
GRANT EXECUTE ON datadog.* to datadog@'%';
GRANT CREATE TEMPORARY TABLES ON datadog.* TO datadog@'%';

DELIMITER $$
CREATE PROCEDURE datadog.explain_statement(IN query TEXT)
    SQL SECURITY DEFINER
BEGIN
    SET @explain := CONCAT('EXPLAIN FORMAT=json ', query);
    PREPARE stmt FROM @explain;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END $$
DELIMITER ;

DELIMITER $$
CREATE PROCEDURE datadog.enable_events_statements_consumers()
    SQL SECURITY DEFINER
BEGIN
    UPDATE performance_schema.setup_consumers SET enabled='YES' WHERE name LIKE 'events_statements_%';
    UPDATE performance_schema.setup_consumers SET enabled='YES' WHERE name = 'events_waits_current';
END $$
DELIMITER ;
GRANT EXECUTE ON PROCEDURE datadog.enable_events_statements_consumers TO datadog@'%';
\n
"

  read -p "Can we Proceed [Y/n]? " go
  while [ $go != "Y" ]; do
    read -p "Can we Proceed [Y/n]? " go
  done
  cp /etc/datadog-agent/conf.d/mysql.d/conf.yaml.example /etc/datadog-agent/conf.d/mysql.d/conf.yaml
  sed -i '42s/.*/password: datadog/' /etc/datadog-agent/conf.d/mysql.d/conf.yaml
  echo "
logs:

    # - type : (mandatory) type of log input source (tcp / udp / file)
    #   port / path : (mandatory) Set port if type is tcp or udp. Set path if type is file
    #   service : (mandatory) name of the service owning the log
    #   source : (mandatory) attribute that defines which integration is sending the log
    #   sourcecategory : (optional) Multiple value attribute. Can be used to refine the source attribute
    #   tags: (optional) add tags to each log collected

  - type: file
    path: /var/log/mysql/mysql_error.log
    source: mysql
    sourcecategory: database
    service: myapplication

  - type: file
    path: /var/log/mysql/mysql-slow.log
    source: mysql
    sourcecategory: database
    service: myapplication

  - type: file
    path: /var/log/mysql/mysql.log
    source: mysql
    sourcecategory: database
    service: myapplication
    # For multiline logs, if they start by the date with the format yyyy-mm-dd uncomment the following processing rule
    # log_processing_rules:
    #   - type: multi_line
    #     name: new_log_start_with_date
    #     pattern: \d{4}\-(0?[1-9]|1[012])\-(0?[1-9]|[12][0-9]|3[01])
    " >>/etc/datadog-agent/conf.d/mysql.d/conf.yaml

  chmod +r /var/log/mysql/*.log
  echo "0 01 * * *    root    chmod +r /var/log/mysql/*.log" >>/etc/crontab

  echo -e "\n\n[*] Restarting mysql server..."

  service mysql restart

  echo -e "[+] Mysql service Restarted..."
}

# ================ SSH Logs ===================

ssh_logs() {
  if ! [ -d '/etc/datadog-agent/conf.d/ssh.d' ]; then
    mkdir /etc/datadog-agent/conf.d/ssh.d
  fi
  echo "  
  #Log section
logs:

    # - type : (mandatory) type of log input source (tcp / udp / file)
    #   port / path : (mandatory) Set port if type is tcp or udp. Set path if type is file
    #   service : (mandatory) name of the service owning the log
    #   source : (mandatory) attribute that defines which integration is sending the log
    #   sourcecategory : (optional) Multiple value attribute. Can be used to refine the source attribute
    #   tags: (optional) add tags to each log collected

  - type: file
    path: /var/log/auth.log
    service: ssh
    source: ssh
" >/etc/datadog-agent/conf.d/ssh.d/conf.yaml

  chmod +r /var/log/auth.log
}

# =============== Postgrsql Logs ===============
postgres_logs() {
  echo -e "\n\n[*] Feature is not Avaibale...\n"
}

# =============== Enable Process Monitoring ============
process_monitoring() {

  echo "
process_config:
  process_collection:
    enabled: true" >>/etc/datadog-agent/datadog.yaml

  echo "
inventories_configuration_enabled: true" >>/etc/datadog-agent/datadog.yaml

  echo -e "[*] Process Monitoring Enabled...\n"
}

# ============= Enable Security Monitoring ==============
security_monitoring() {
  cp /etc/datadog-agent/security-agent.yaml.example /etc/datadog-agent/security-agent.yaml
  cp ./system-probe.yaml /etc/datadog-agent/system-probe.yaml

  echo "
runtime_security_config:
 ## @param enabled - boolean - optional - default: false
 ## Set to true to enable the Security Runtime Module.
 #
 enabled: true

compliance_config:
 ## @param enabled - boolean - optional - default: false
 ## Set to true to enable CIS benchmarks for CSPM.
 #
 enabled: true" >>/etc/datadog-agent/security-agent.yaml

  echo -e "[+] Security Monitoring Enabled...\n"
}

# ============= Enable APM in PHP ===============
php_apm() {
  curl -LO https://github.com/DataDog/dd-trace-php/releases/latest/download/datadog-setup.php
  php datadog-setup.php --php-bin=all --enable-appsec --enable-profiling
  echo -e "[+] APM Monitoring Enabled...\n"
}

# =============== Starting Script ===============

enable_service() {
  local service=${1:--1}
  echo -e "\n\n[*] Select the Service to Enable logs...\n"
  echo -e "1. Apache2\n2. Nginx\n3. Mysql\n4. SSH\n0. Done\n"
  read service
  if [ "$service" -eq -1 ]; then
    echo -e "\n[+] Logging Service Enbaled.\n"
  elif [ "$service" -eq 1 ]; then
    echo -e "\n[*] Enbaling Apache2 Logs..."
    sleep 3
    if [ -d "/var/log/apache2" ]; then
      apache_logs
      echo -e "[+] Apache2 Logs are Enabled...\n"
      sleep 1
    else
      sleep 1
      echo -e "\n[!] Apache Seems to be not Installed in your system\n."
      sleep 1
    fi
  elif [ "$service" -eq 2 ]; then
    echo -e "\n[*] Enbaling Nginx Logs..."
    sleep 3
    if [ -d "/var/log/nginx" ]; then
      nginx_logs
      echo -e "[+] Nginx Logs are Enabled...\n"
      sleep 1
    else
      sleep 1
      echo -e "\n[!] Nginx Seems to be not Installed in your system\n."
      sleep 1
    fi

  elif [ "$service" -eq 3 ]; then
    echo -e "\n[*] Enbaling Mysql Logs..."
    sleep 3
    if [ -d '/etc/mysql' ]; then
      mysql_logs
      echo -e "[+] Mysql Logs are Enabled...\n"
      sleep 1
    else
      sleep 1
      echo -e "\n[!] Mysql Seems to be not Installed in your system\n."
      sleep 1
    fi
  elif [ "$service" -eq 4 ]; then
    echo -e "\n[*] Enbaling SSH Logs..."
    sleep 3
    ssh_logs
    echo -e "[+] SSH Logs are Enabled...\n"
    sleep 1
  else
    echo -e "\n[*] Enbaling Security Monitoring..."
    sleep 3
    security_monitoring
    sleep 1
    echo -e "\n[*] Enbaling Process Monitoring..."
    sleep 3
    process_monitoring
    sleep 1
    # echo -e "\n[*] Enbaling PHP APM Service..."
    # sleep 3
    # php_apm
    # sleep 1
    echo -e "\n[*] Restarting Datadog Agent Service..."
    service datadog-agent restart
    echo -e "\n[+] Datadog Agent Service restarted Successfully...\n"

  fi

  if [ "$service" -ne 0 ]; then
    enable_service
  fi

}

enable_service
