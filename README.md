# **homelab_2023**
# my setup: Proxmox -> debian VM (docker containers) -> services (Traefik, Cloudflare, OAuth, Portainer, Homepage, Jellyfin, ...)

## install docker
```
# uninstall old version
sudo apt-get remove docker docker-engine docker.io containerd runc

# install through convenience script
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# add docker group to user, logout then login again
sudo usermod -aG docker <user>

# install docker compose plugin
sudo apt-get update
sudo apt-get install docker-compose-plugin
```

## create docker file and services
```
# create custom bridge for all services
docker network create backend
docker network create frontend
```
### environment file
> Note: all sensitive file should own by root:root only and have 600 permission (exp: .env, acme.json, secrets/)
```
PUID=1000
PGID=1000
TZ=America/Vancouver
DOCKERDIR=/path-to-docker-folder
SECRETSDIR=/path-to-docker-folder/secrets
DATADIR=/path-to-media-dir

# traefik cloudflare config
DOMAINNAME_CLOUD_SERVER=your-dns-name.com
CLOUDFLARE_EMAIL=your-email@provider.com

# trusted IPs
LOCAL_IPS=127.0.0.1/32,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12
CLOUDFLARE_IPS=173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22

# cloudflare api key for ddns
CF_API_TOKEN=your-token
```

## cloudflare tunnel service
### high level view
![cloudflare and traefik](https://user-images.githubusercontent.com/33076940/233897278-90d8b818-1036-489b-a8ad-b8e09ed09cd9.png)
### DNS entries (turn off proxy orange for testing first)
![cloudflare DNS entries](https://file.notion.so/f/s/be89ff02-34ac-4f22-a3e6-19d94a90ed99/Untitled.png?id=0b233128-98b0-431e-8bce-e0a2f376f0d1&table=block&spaceId=614b6291-41d9-4f52-9e1e-cea413e4f8c1&expirationTimestamp=1682396240360&signature=siArZH8X73cyv2f43DeOYqPtKDG7MSTfVKIU2FF-Zrs&downloadName=Untitled.png)
### SSL/TLS Options: Full Strict
### Edge Certificates
- **Always Use HTTPS: ON**
- **HTTP Strict Transport Security (HSTS): Enable**
- **Minimum TLS Version: 1.2**
- **Opportunistic Encryption: ON**
- **TLS 1.3: ON**
- **Automatic HTTPS Rewrites: ON**
- **Certificate Transparency Monitoring: ON**
### Firewall Rules: add any region/IP you want to allow/block
### Firewall Settings
- **Security Level: High**
- **Bot Fight Mode: ON**
- **Challenge Passage: 30 Minutes**
- **Browser Integrity Check: ON**
### Speed: Optimization
- **Auto Minify: OFF**
- **Brotli: ON**
- **Rocket Loader: OFF**
### Caching Configuration
- **Caching Level: Standard**
- **Browser Cache TTL: 1 hour**
- **Always Online: OFF**
### Page Rules
![cloudflare page rules](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/9c4172ab-b15b-410b-85c7-d0f23ed89d93/Untitled.png)
- first one turn off SSL when Traefik tries to fetch LetsEncrypt SSL certs
- second one for media service (jellyfin, flex) to bypass Cloudflare resources since caching media content require significant amount of Cloudflare resources —> they can suspend your account.

## Cloudflare DNS updater: update your WAN IP to DNS record
### create API Token on cloudflare
![cloudflare API Token for cloudflare updater service](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/95a8d7bd-0d2c-4528-81e9-6aa074ac0287/Untitled.png)
```
# Cloudflare DDNS - Dynamic DNS Updater
  cf-ddns:
    container_name: cf-ddns
    image: oznu/cloudflare-ddns:latest
    restart: always
    environment:
      - API_KEY=$CF_API_TOKEN
      - ZONE=$DOMAINNAME_CLOUD_SERVER
      - PROXIED=true
      - RRTYPE=A
      - DELETE_ON_STOP=false
      - DNS_SERVER=1.1.1.1
    networks:
      - t2_proxy
```

## traefik service (credit: [traefik-docker-compose-guide-2022](https://www.smarthomebeginner.com/traefik-docker-compose-guide-2022/))
- cloudflare Domain, add A & CNAME records
- port forward traefik 80 & 443 on router
- Note:
  - chmod 600 for acme.json
  - Access the site from same network as the docker-traefik container might not work → comment out staging certs line & turn on cloudflare proxy for the 2 records above
```
---
version: "3.9"

networks:
  default:
    driver: bridge
  t2_proxy:
    name: t2_proxy
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.90.0/24

# Common environment values
x-environment: &default-tz-puid-pgid
  TZ: $TZ
  PUID: $PUID
  PGID: $PGID
 
# Keys common to some of the core services that we always to automatically restart on failure
x-common-keys-core: &common-keys-core
  networks:
    - t2_proxy
  security_opt:
    - no-new-privileges:true
  restart: always
 
# Keys common to some of the dependent services/apps
x-common-keys-apps: &common-keys-apps
  networks:
    - t2_proxy
  security_opt:
    - no-new-privileges:true
  restart: unless-stopped
 
# Keys common to some of the services in media-services.txt
x-common-keys-media: &common-keys-media
  networks:
    - t2_proxy
  security_opt:
    - no-new-privileges:true
  restart: "no"

########################### SERVICES
services:
############################# FRONTENDS
  traefik:
    <<: *common-keys-core # See EXTENSION FIELDS at the top
    container_name: "traefik"
    image: "traefik:v2.9.10"
    command: # CLI arguments
      - --global.checkNewVersion=true
      - --global.sendAnonymousUsage=true
      - --entryPoints.http.address=:80
      - --entryPoints.https.address=:443
      # Allow these IPs to set the X-Forwarded-* headers - Cloudflare IPs: https://www.cloudflare.com/ips/
      - --entrypoints.https.forwardedHeaders.trustedIPs=$CLOUDFLARE_IPS,$LOCAL_IPS
      - --entryPoints.traefik.address=:8080
      - --api=true
      # - --api.insecure=true
      - --api.dashboard=true
      # - --serversTransport.insecureSkipVerify=true
      - --log=true
      - --log.filePath=/logs/traefik.log
      - --log.level=INFO # (Default: error) DEBUG, INFO, WARN, ERROR, FATAL, PANIC
      - --accessLog=true
      - --accessLog.filePath=/logs/access.log
      - --accessLog.bufferingSize=100 # Configuring a buffer of 100 lines
      - --accessLog.filters.statusCodes=204-299,400-499,500-599
      - --providers.docker=true
      - --providers.docker.endpoint=unix:///var/run/docker.sock # Use Docker Socket Proxy instead for improved security
      # - --providers.docker.endpoint=tcp://socket-proxy:2375 # Use this instead of the previous line if you have socket proxy.
      - --providers.docker.exposedByDefault=false
      - --entrypoints.https.http.tls.options=tls-opts@file
      # Add dns-cloudflare as default certresolver for all services. Also enables TLS and no need to specify on individual services
      - --entrypoints.https.http.tls.certresolver=dns-cloudflare
      - --entrypoints.https.http.tls.domains[0].main=$DOMAINNAME_CLOUD_SERVER
      - --entrypoints.https.http.tls.domains[0].sans=*.$DOMAINNAME_CLOUD_SERVER
      # - --entrypoints.https.http.tls.domains[1].main=$DOMAINNAME2 # Pulls main cert for second domain
      # - --entrypoints.https.http.tls.domains[1].sans=*.$DOMAINNAME2 # Pulls wildcard cert for second domain
      - --providers.docker.network=t2_proxy
      - --providers.docker.swarmMode=false
      - --providers.file.directory=/rules # Load dynamic configuration from one or more .toml or .yml files in a directory
      # - --providers.file.filename=/path/to/file # Load dynamic configuration from a file
      - --providers.file.watch=true # Only works on top level files in the rules folder
      # - --certificatesResolvers.dns-cloudflare.acme.caServer=https://acme-staging-v02.api.letsencrypt.org/directory # LetsEncrypt Staging Server - uncomment when testing
      - --certificatesResolvers.dns-cloudflare.acme.email=$CLOUDFLARE_EMAIL
      - --certificatesResolvers.dns-cloudflare.acme.storage=/acme.json
      - --certificatesResolvers.dns-cloudflare.acme.dnsChallenge.provider=cloudflare
      - --certificatesResolvers.dns-cloudflare.acme.dnsChallenge.resolvers=1.1.1.1:53,1.0.0.1:53
      - --certificatesResolvers.dns-cloudflare.acme.dnsChallenge.delayBeforeCheck=90 # To delay DNS check and reduce LE hitrate
    networks:
      t2_proxy:
        ipv4_address: 192.168.90.254
    ports:
      - target: 80
        published: 80
        protocol: tcp
        mode: host
      - target: 443
        published: 443
        protocol: tcp
        mode: host
      # - target: 8080 # insecure api wont work
      #   published: 8080
      #   protocol: tcp
      #   mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro # If you use Docker Socket Proxy, comment this line out
      - $DOCKERDIR/appdata/traefik2/rules/cloudserver:/rules # file provider directory
      - $DOCKERDIR/appdata/traefik2/acme/acme.json:/acme.json # cert location - you must create this empty file and change permissions to 600
      - $DOCKERDIR/logs/cloudserver/traefik:/logs # for fail2ban or crowdsec
      - $DOCKERDIR/appdata/traefik2/shared:/shared
    environment:
      - TZ=$TZ
      - CF_API_EMAIL=$CLOUDFLARE_EMAIL
      - CF_API_KEY=$CLOUDFLARE_API_KEY
      - DOMAINNAME_CLOUD_SERVER # Passing the domain name to the traefik container to be able to use the variable in rules. 
    labels:
      - "traefik.enable=true"
      # HTTP-to-HTTPS Redirect
      - "traefik.http.routers.http-catchall.entrypoints=http"
      - "traefik.http.routers.http-catchall.rule=HostRegexp(`{host:.+}`)"
      - "traefik.http.routers.http-catchall.middlewares=redirect-to-https"
      - "traefik.http.middlewares.redirect-to-https.redirectscheme.scheme=https"
      # HTTP Routers
      - "traefik.http.routers.traefik-rtr.entrypoints=https"
      - "traefik.http.routers.traefik-rtr.rule=Host(`traefik.$DOMAINNAME_CLOUD_SERVER`)"
      - "traefik.http.routers.traefik-rtr.tls=true" # Some people had 404s without this
      # - "traefik.http.routers.traefik-rtr.tls.certresolver=dns-cloudflare" # Comment out this line after first run of traefik to force the use of wildcard certs
      - "traefik.http.routers.traefik-rtr.tls.domains[0].main=$DOMAINNAME_CLOUD_SERVER"
      - "traefik.http.routers.traefik-rtr.tls.domains[0].sans=*.$DOMAINNAME_CLOUD_SERVER"
      # - "traefik.http.routers.traefik-rtr.tls.domains[1].main=$DOMAINNAME2" # Pulls main cert for second domain
      # - "traefik.http.routers.traefik-rtr.tls.domains[1].sans=*.$DOMAINNAME2" # Pulls wildcard cert for second domain
      ## Services - API
      - "traefik.http.routers.traefik-rtr.service=api@internal"
      ## Middlewares
      - "traefik.http.routers.traefik-rtr.middlewares=chain-basic-auth@file"
```
## switch to docker secrets
- create secrets folder at `$DOCKERDIR`
- set owner:group to root, and chmod 600
- create files: (cf_api_key, cf_email, …)
- Remember to add `$SECRETSDIR` to the environment file
```
# docker compose file - after the network section
########################### SECRETS
secrets:
  cf_email:
    file: $SECRETSDIR/cf_email
  cf_api_key:
    file: $SECRETSDIR/cf_api_key

# adding secrets and environment for traefik service
services:
	traefik:
		....
		secrets: #makes the secret file available at /run/secrets folder inside the container.
	      - cf_email
	      - cf_api_key
	      - htpasswd
		environment:
	      - TZ=$TZ
	      - CF_API_EMAIL_FILE=/run/secrets/cf_email
	      - CF_API_KEY_FILE=/run/secrets/cf_api_key
	      - HTPASSWD_FILE=/run/secrets/htpasswd # HTPASSWD_FILE can be whatever as it is not used/called anywhere.
	      - DOMAINNAME_CLOUD_SERVER # Passing the domain name to traefik container to be able to use the variable in rules.

# change the user file in middlewares.yml
http:
  middlewares:
    middlewares-basic-auth:
      basicAuth:
        usersFile: "/run/secrets/htpasswd" # be sure to mount the volume through docker-compose.yml
        realm: "Traefik 2 Basic Auth"
```

## switch to docker socket
- edit the `/etc/default/docker` file and add `DOCKER_OPTS="--iptables=false"` so the docker respect the IP firewall table
```
# add socket_proxy in network section (at the top of docker compose file)
networks:
  socket_proxy:
    name: socket_proxy
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.91.0/24

# socket-proxy in the `services` section
# Docker Socket Proxy - Security Enchanced Proxy for Docker Socket
  socket-proxy:
    <<: *common-keys-core # See EXTENSION FIELDS at the top
    container_name: socket-proxy
    image: tecnativa/docker-socket-proxy
    networks:
      socket_proxy:
        ipv4_address: 192.168.91.254 # You can specify a static IP
    # privileged: true # true for VM. False for unprivileged LXC container.
    # ports:
      # - "127.0.0.1:2375:2375" # Port 2375 should only ever get exposed to the internal network. When possible use this line.
    # I use the next line instead, as I want portainer to manage multiple docker endpoints within my home network.
    # - "2375:2375"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock"
    environment:
      - LOG_LEVEL=info # debug,info,notice,warning,err,crit,alert,emerg
      ## Variables match the URL prefix (i.e. AUTH blocks access to /auth/* parts of the API, etc.).
      # 0 to revoke access.
      # 1 to grant access.
      ## Granted by Default
      - EVENTS=1
      - PING=1
      - VERSION=1
      ## Revoked by Default
      # Security critical
      - AUTH=0
      - SECRETS=0
      - POST=1 # Watchtower
      # Not always needed
      - BUILD=0
      - COMMIT=0
      - CONFIGS=0
      - CONTAINERS=1 # Traefik, portainer, etc.
      - DISTRIBUTION=0
      - EXEC=0
      - IMAGES=1 # Portainer
      - INFO=1 # Portainer
      - NETWORKS=1 # Portainer
      - NODES=0
      - PLUGINS=0
      - SERVICES=1 # Portainer
      - SESSION=0
      - SWARM=0
      - SYSTEM=0
      - TASKS=1 # Portainer
      - VOLUMES=1 # Portainer
```

## add google oauth
- oauth service docker compose file
- google cloud console → add project → filled oauth consent screen → create oauth client ID credentials
- add middleware oauth
- add middleware chain (watch out for indentation: tab, space; it can break the app → check logs if not working)
- Note: for bypassing certain services like Radarr check the link from google oauth guide
```
# Google OAuth - Single Sign On using OAuth 2.0
  # https://www.smarthomebeginner.com/google-oauth-with-traefik-docker/
  oauth:
    <<: *common-keys-core # See EXTENSION FIELDS at the top
    container_name: oauth
    image: thomseddon/traefik-forward-auth:latest
    # image: thomseddon/traefik-forward-auth:2.1-arm # Use this image with Raspberry Pi
    # Allow apps to bypass OAuth. Radarr example below will bypass OAuth if API key is present in the request (eg. from NZB360 mobile app).
    # While this is one way, the recommended way is to bypass authentication using Traefik labels shown in some of the -Arr apps in this file.
    # command: --rule.radarr.action=allow --rule.radarr.rule="Headers(`X-Api-Key`, `$RADARR_API_KEY`)"
    # command: --rule.sabnzbd.action=allow --rule.sabnzbd.rule="HeadersRegexp(`X-Forwarded-Uri`, `$SABNZBD_API_KEY`)"
    environment:
      - CONFIG=/config
      - COOKIE_DOMAIN=$DOMAINNAME_CLOUD_SERVER
      - INSECURE_COOKIE=false
      - AUTH_HOST=oauth.$DOMAINNAME_CLOUD_SERVER
      - URL_PATH=/_oauth
      - LOG_LEVEL=warn # set to trace while testing bypass rules
      - LOG_FORMAT=text
      - LIFETIME=86400 # 1 day
      - DEFAULT_ACTION=auth
      - DEFAULT_PROVIDER=google
    secrets:
      - source: traefik_forward_auth
        target: /config
    labels:
      - "traefik.enable=true"
      ## HTTP Routers
      - "traefik.http.routers.oauth-rtr.tls=true"
      - "traefik.http.routers.oauth-rtr.entrypoints=https"
      - "traefik.http.routers.oauth-rtr.rule=Host(`oauth.$DOMAINNAME_CLOUD_SERVER`)"
      ## Middlewares
      - "traefik.http.routers.oauth-rtr.middlewares=chain-oauth@file"
      ## HTTP Services
      - "traefik.http.routers.oauth-rtr.service=oauth-svc"
      - "traefik.http.services.oauth-svc.loadbalancer.server.port=4181"

# middlewares.yml
middlewares-oauth:
      forwardAuth:
        address: "http://oauth:4181" # Make sure you have the OAuth service in docker-compose.yml
        trustForwardHeader: true
        authResponseHeaders:
          - "X-Forwarded-User"

# middlewares-chains.yml
chain-oauth:
      chain:
        middlewares:
          - middlewares-rate-limit
          - middlewares-https-redirectscheme
          - middlewares-secure-headers
          - middlewares-oauth
          - middlewares-compress
```
