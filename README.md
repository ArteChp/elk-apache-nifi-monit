# Guide to Monitoring with ELK, Apache NiFi, Grafana
## **Introduction**

The purpose of my work was to install and configure Elasticsearch (alongside Kibana), and Apache NiFi on a Ubuntu VM, and use them to construct simple data pipelines. I aimed to build a pipeline in NiFi that accepts syslog on local port UDP 514 and sends it on to Elasticsearch. Additionally, I used Filebeat and Logstash to create a pipeline in NiFi to gather data from /var/log/syslog (Ubuntu) and forward it to Elasticsearch. 

Furthermore, I explored the potential of InfluxDB and Telegraf for monitoring the performance and operational status of the operating system and NiFi. In order to effectively visualize the gathered data, Grafana was implemented as a visualization tool for data from InfluxDB.


## Methodology

### Creation and Setup Ubuntu VM

A virtual environment was created using Ubuntu Virtual Machine v22.04.2 on Virtualbox v7.0.8.

### Installation of ElasticSearch, Kibana, Filebeat, Logstash 

Following software were installed: ElasticSearch v8.8.1, Kibana v8.8.1, Filebeat v8.8.1, Logstash v1:8.8.1. The following command was executed to perform the installation:
```
$ wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

$ sudo apt-get install apt-transport-https

$ echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

$ sudo apt-get update && sudo apt-get install elasticsearch kibana filebeat logstash
```

### Configuration of ElasticSearch and Kibana

1.  ElasticSearch's configuration file was modified as follows:

```
$ sudo vim /etc/elasticsearch/elasticsearch.yml
```

Edited the file to include:

```
network.host: localhost
http.port: 9200
discovery.type: single-node # Used one node for the test stack
xpack.security.enabled: true # Enabled security 
xpack.security.enrollment.enabled: true
```

2. Similarly, Kibana's configuration file was updated:

```
sudo vim /etc/kibana/kibana.yml
```

Edited the file to include:

```
server.port: 5601
server.host: "localhost"
elasticsearch.hosts: ["http://localhost:9200"]
elasticsearch.username: "kibana_system"
```

3. Enabled and started ElasticSearch and Kibana services using systemctl commands:
```
$ sudo systemctl daemon-reload
$ sudo systemctl enable elasticsearch.service
$ sudo systemctl enable kibana.service
$ sudo systemctl start elasticsearch.service
$ sudo systemctl start kibana.service
```

4. Created tokens and updated passwords to connect ElasticSearch and Kibana:
```
$ sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
$ sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
$ sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -a -u kibana_system
```

5. Tested Kibana in a browser using the URL: http://localhost:5601


### Installation and Configuration of Apache NiFi

1.  Apache NiFi v1.22.0 was downloaded and installed using the following commands:
```
$ cd ~/Downloads
$ wget https://www.apache.org/dyn/closer.lua?path=/nifi/1.22.0/nifi-1.22.0-bin.zip
$ unzip ./nifi-1.22.0-bin.zip
$ sudo mv ~/Downloads/nifi-1.22.0-bin /opt/nifi

```
2. A separate user 'nifi' was created and granted read permissions for syslog for security reasons. The principle of least privilege was followed, which minimizes potential damage by restricting access rights for users to the bare minimum permissions they need to perform their work.
```
$ sudo adduser nifi

# Set permissions to read syslog
$ sudo usermod -aG adm nifi 
$ sudo setfacl -m u:nifi:rw /var/log

# Set working directory and permissions
$ sudo usermod -m -d /opt/nifi nifi 
$ sudo chown -R nifi:nifi /opt/nifi/
```

3. Java was installed and environment variables were set for all users:
```
$ sudo apt-get install openjdk-11-jdk
```

Updated /etc/environment file to include:
```
JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin:$JAVA_HOME/bin"
```

4. A systemd service for NiFi was created:

```
$ sudo vim /lib/systemd/system/nifi.service
```

With the following service configuration:

```
[Unit]
Description=Apache NiFi
After=network.target syslog.target

[Service]
Type=forking

User=nifi
Group=nifi

WorkingDirectory=/opt/nifi
EnvironmentFile=/etc/environment
ExecStart=/opt/nifi/bin/nifi.sh start
ExecStop=/opt/nifi/bin/nifi.sh stop
ExecRestart=/opt/nifi/bin/nifi.sh restart 

RestartSec=5
Restart=always

StandardOutput=syslog
StandardError=syslog

SyslogIdentifier=nifi

[Install]
WantedBy=multi-user.target
```

5. Enabled and started the NiFi service:

```
$ sudo systemctl daemon-reload
$ sudo systemctl enable nifi.service
$ sudo systemctl start nifi.service
```


## Installation and Configuration of InfluxDB, Telegraf and Grafana

1. Installed InfluxDB v2.7.1 and Telegraf v1.27.0 using the provided scripts.

```
cd ~/Downloads 

wget -q https://repos.influxdata.com/influxdata-archive_compat.key && echo '393e8779c89ac8d958f81f942f9ad7fb82a25e133faddaf92e15b16e6ac9ce4c influxdata-archive_compat.key' | sha256sum -c && cat influxdata-archive_compat.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg  && echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' | sudo tee /etc/apt/sources.list.d/influxdata.list  
sudo apt-get update && sudo apt-get install influxdb2

wget -q https://repos.influxdata.com/influxdata-archive_compat.key && echo '393e8779c89ac8d958f81f942f9ad7fb82a25e133faddaf92e15b16e6ac9ce4c influxdata-archive_compat.key' | sha256sum -c && cat influxdata-archive_compat.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg && echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' | sudo tee /etc/apt/sources.list.d/influxdata.list && sudo apt-get update && sudo apt-get install telegraf
```

2. Configured InfluxDB and set the HTTP binding address.
```
$ sudo vim /etc/influxdb/config.toml
```

Edited the file to include:

```
http-bind-address = ":8086"
```

3. Setup InfluxDB, created a user, an organization, a database, and generated an authorization token.
```
$ influx setup
$ influx auth create   --org A   --operator
```

4. Configured Telegraf for OS and NiFi monitoring.
```
$ sudo vim /etc/telegraf/telegraf.conf
```

Edited the file to include:

```
 [[outputs.influxdb_v2]]
   urls = ["http://127.0.0.1:8086"]
   token = "KshrEJVzWgzLuqgYd9r1CrEnDPLkqIVE8gUAkigUx2DD1NMtBBbMsE95kQOoj_zy9BzelDfFjsVgFLVH38TkLA=="
   organization = "A"
   bucket = "admin"
   
[[inputs.http]]
   urls = [
     "https://localhost:8443/nifi-api/system-diagnostics/jmx-metrics"
   ]
    method = "GET"
	tls_ca = "/etc/telegraf/ca.pem"
    tls_cert = "/etc/telegraf/cert.pem"
    tls_key = "/etc/telegraf/key.pem"
    insecure_skip_verify = true
	
	data_format = "json"
    json_query = "jmxMetricsResults"
    tag_keys = ["beanName"]
    json_string_fields = ["attributeName"]


[[inputs.cpu]]
  percpu = true
  totalcpu = true
  collect_cpu_time = false
  report_active = false
  core_tags = false

[[inputs.disk]]
  ignore_fs = ["tmpfs", "devtmpfs", "devfs", "iso9660", "overlay", "aufs", "squashfs"]

[[inputs.diskio]]

[[inputs.kernel]]

[[inputs.mem]]
```

5. Setup of a certificate for accessing NiFi JMX metrics
```
$ cd /opt/nifi/conf

$ openssl pkcs12 -in keystore.p12 -out intermediate_key.pem -nodes
$ openssl pkcs12 -in truststore.p12 -out intermediate_ca.pem -nodes

$ openssl x509 -in intermediate_key.pem -out cert.pem
$ openssl rsa -in intermediate_key.pem -out key.pem
$ openssl x509 -in intermediate_ca.pem -out ca.pem

$ sudo chown telegraf:telegraf ca.pem cert.pem key.pem
$ sudo chmod 400 cert.pem key.pem
$ sudo chmod 444 ca.pem

$ sudo mv *.pem /etc/telegraf/
```

6. Installed Grafana v10.0.1. using the provided scripts:
```
$ cd ~/Downloads
$ sudo apt-get install -y adduser libfontconfig1
$ wget https://dl.grafana.com/enterprise/release/grafana-enterprise_10.0.1_amd64.deb
$ sudo apt install ./grafana-enterprise_10.0.1_amd64.deb
```


### Configuration of Filebeat and Logstash

1. Configured Filebeat to listen to syslog (because it's Ubuntu) and forward the data to Logstash.

```
$ sudo vim /etc/filebeat/filebeat.yml
```

Edited the file to include:
```
filebeat.inputs:

- type: filestream
  id: syslog
  enabled: true
  paths:
    - /var/log/syslog
  encoding: utf8
  
output.logstash:
   hosts: ["localhost:5044"]
```

2. Created a Logstash pipeline to receive data from Filebeat and send JSON data as UDP on port 514.

```
$ sudo vim /etc/logstash/conf.d/nifi.conf
```

Edited the file to include:
```
input {
  beats {
    port => 5044
  }
}

output {
  udp {
    host => "localhost"
    port => 514
    codec => json_lines { target => "nifi" }
  }
}

```

3. Enabled and started Filebeat and Logstash services.
```
$ sudo systemctl daemon-reload
$ sudo systemctl enable filebeat.service
$ sudo systemctl enable logstash.service
$ sudo systemctl start filebeat.service
$ sudo systemctl start logstash.service
```



### Building a Simple NiFi Pipeline to Accept Syslog on Local UDP Port 514 and Forward it to ElasticSearch
1. Logged into NiFi at https://localhost:8443/nifi/
2. Created and set up the 'ListenUDP' processor for localhost:514:

![ListenUDP](https://i.imgur.com/C6EmyIK.png)

4. Created and set up the 'PutElasticsearchJson' processor:

![PutElasticsearchJson](https://i.imgur.com/iMIFsQ4.png)

4. Created and set up the 'ElasticSearchClientServiceImpl' processor:

![ElasticSearchClientServiceImpl](https://i.imgur.com/Niq2T04.png)

![ElasticSearchClientServiceImpl](https://i.imgur.com/68ubM6d.png)



### Building a Simple NiFi Pipeline to Gather Data from the Local '/var/log/syslog' and Forward it to ElasticSearch

The setup from the previous steps has already configured this functionality. Here's the visualization of the pipeline:

![NiFi Pipeline](https://i.imgur.com/uLbBZOC.png)



### Testing the Setup with a Query in Kibana Console

![Kibana Console](https://i.imgur.com/fo0XidA.png)



## Results and Observations

### Visualization of Metrics from Kibana Dashboard - Count of Records by Timestamp over the Last Three Days

![Kibana Dashboard](https://i.imgur.com/ccZ6vIg.png)

The following chart demonstrates the count of records by timestamp over the past three days. The irregularity of the data is because the VM system was only operational during working hours.


### OS Metrics - CPU Total Usage

Here's the visual representation of the total CPU usage:

![CPU Total Usage](https://i.imgur.com/GHcKMak.png)



### OS Metrics - Disk Usage

The following chart represents the disk usage:

![Disk Usage](https://i.imgur.com/qa3tZFw.png)


### Metrics from NiFi

Finally, here are the gathered metrics from NiFi:

![NiFi Metrics](https://i.imgur.com/C11EHbW.png)


Through our setup, I implemented a pipeline that collected system log and NiFi metrics and stored them in an ElasticSearch and InfluxDB databases. Here are the summarized outcomes and insights:

1. **Real-Time Monitoring:** The pipeline enabled near real-time monitoring of system logs, visualized through Kibana and Grafana. These provide a basis for immediate troubleshooting and proactive management.
2. **Visualization of System Metrics:** The use of Kibana and Grafana allowed us to visually observe system trends and performance over time via graphs depicting CPU and disk usage.
3. **Insights into NiFi Metrics:** Metrics extracted from Apache NiFi showed how well the NiFi processors in our setup performed.
4. **On-Demand Data Analysis:** By having our data in ElasticSearch and InfluxDB, we facilitated on-demand querying and data analysis via Kibana and Grafana.

## Challenges and Solutions

During this project, several challenges arose that provided a valuable learning experience.

1. The use of ELK and Apache NiFi was new to me, which presented a learning curve. However, leveraging resources such as ChatGPT 4, Google search, and thorough documentation enabled me to rapidly familiarize myself with these technologies.
2. The most time-consuming aspect of the project was figuring out how to monitor Apache NiFi, particularly given the differences between the new version and previous ones. Traditional Java application monitoring methods (JMXremote) proved unhelpful. After delving into the updated documentation, I discovered that the new version provides a dedicated API for JMX remote.
3. Initially, parsing data of NiFi's JMX API was impossible without authentication. This necessitated the conversion of certificates from PKCS#12 to PEM format, and the subsequent configuration of Telegraf to recognize them.
4. Initially, I encountered difficulties in parsing syslog data with NiFi's native processor because Ubuntu uses the Traditional log format. I initially changed this to the RFC3164 or RFC5424 standard. However, upon installing Filebeat and Logstash, I realized this change was unnecessary, as Filebeat is capable of parsing the Traditional log format.

Each one provided an opportunity to gain new knowledge and hone problem-solving skills. I am confident that this experience will be beneficial in future projects.

Despite the successes, I identified areas that need improvement:

- **Reliable Data Transmission:** While the data pipeline transmitted information consistently, there's room to bolster reliability further. This could involve implementing error-checking protocols or redundancy mechanisms to ensure no data loss.
- **Scalable Setup:** The current setup provides a foundation for scalability. However, to truly accommodate larger environments or complex setups, the infrastructure needs enhancements. The use of Docker containers could streamline deployment and operation of pipeline components across various environments. Furthermore, leveraging cloud services could provide scalable storage and processing capabilities, making the system robust enough to handle increased data volume and complexity.

##### Security Considerations

In addition to the improvements, the following security practices should be considered while transitioning this setup into a production environment:

1. **Secure Connections:** Leverage HTTPS instead of HTTP to safeguard data during transmission.
2. **Robust Authentication:** Implement complex passwords and secure key pair generation, alongside two-factor authentication where feasible.
3. **Access Controls:** Utilize role-based access control (RBAC) to regulate data and function accessibility.
4. **Regular Updates:** Consistently update the software stack to incorporate the newest security patches.
5. **Network Security:** Adopt network-level protections like firewalls and network segmentation. Use VPNs for remote system access.
6. **Audit Logs:** Continuously review logs to spot any abnormal system activities.
7. **Encrypted Storage:** Maintain sensitive data in an encrypted format.
8. **Intrusion Detection and Prevention:** Use Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) to detect and counter potential security threats.
9. **Backup and Recovery:** Regularly backup data and ensure a robust disaster recovery plan is in place.
10. **Security Testing:** Undertake frequent security audits, vulnerability assessments, and penetration testing to detect and rectify security issues.
11. **Team Education:** Cultivate a security-aware culture within the team, emphasizing practices like password security, phishing recognition, and more.

Incorporating these strategies will significantly enhance the system's security posture, ensuring it is ready for a safe production deployment.
