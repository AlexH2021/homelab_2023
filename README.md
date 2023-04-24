# **homelab_2023**
#docker containers

##install docker
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

##create docker file and services
```
# create custom bridge for all services
docker network create backend
docker network create frontend
```

##cloudflare tunnel service
![](https://file.notion.so/f/s/70d85704-c12b-4f62-9a50-5f6ddae52c8d/Untitled.png?id=415b738a-6f25-4652-9543-44e0ffaad40a&table=block&spaceId=614b6291-41d9-4f52-9e1e-cea413e4f8c1&expirationTimestamp=1682394195859&signature=XXlcyVS9Ph3tlY3_nlTX4Iw50MXFJ4oncYpbrkCfRB8&downloadName=Untitled.png)
```
wait here
```

##traefik service

```
code
```
