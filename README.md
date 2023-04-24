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

## cloudflare tunnel service
### high level view
![cloudflare and traefik](https://user-images.githubusercontent.com/33076940/233897278-90d8b818-1036-489b-a8ad-b8e09ed09cd9.png)

### DNS entries (turn off proxy orange for testing first)
![cloudflare DNS entries](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/baef43c2-9803-4d1d-98ac-6444616b68c7/Untitled.png)
### SSL/TLS Options: Full Strict
### Edge Certificates
- **Always Use HTTPS: ON**
- **HTTP Strict Transport Security (HSTS): Enable**
- **Minimum TLS Version: 1.2**
- **Opportunistic Encryption: ON**
- **TLS 1.3: ON**
- **Automatic HTTPS Rewrites: ON**
- **Certificate Transparency Monitoring: ON**

```
wait here
```

## traefik service

```
code
```
