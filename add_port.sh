PORT="$1"
CONTAINER_IP="$2"
if [ -z "$CONTAINER_IP" ]
then
    return
else
    echo "PROCEEDING TO REGISTER PORT"
fi
tail -n 1 /etc/nginx/nginx.conf | wc -c | xargs -I {} truncate /etc/nginx/nginx.conf -s -{}
echo "
	server {
		listen 0.0.0.0:$((PORT+1));
		proxy_pass $CONTAINER_IP:19133;
	}
	server {
		listen 0.0.0.0:$PORT;
		proxy_pass $CONTAINER_IP:19132;
	}
	server {
		listen 0.0.0.0:$((PORT+1)) udp;
		proxy_pass $CONTAINER_IP:19133;
	}
	server {
		listen 0.0.0.0:$PORT udp;
		proxy_pass $CONTAINER_IP:19132;
	}
	server {
		listen 0.0.0.0:$((PORT+2));
		proxy_pass $CONTAINER_IP:30000;
	}

}" >> /etc/nginx/nginx.conf

nginx -s reload
