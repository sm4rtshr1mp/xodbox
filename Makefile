.DEFAULT_GOAL := start

pull:
	docker pull node:alpine

stop:
	docker stop xodbox-prod txt-xodbox-prod
	docker rm xodbox-prod txt-xodbox-prod

start:
	docker run -d \
		--name xodbox-prod \
		--restart=always \
		-v $(shell pwd)/server.js:/usr/src/app/server.js:ro \
		--expose 3000 \
		--env-file xodbox.env \
		--user 1000 \
		node:alpine node /usr/src/app/server.js
	docker run -d \
		--name txt-xodbox-prod \
		--restart=always \
		-v $(shell pwd)/server.js:/usr/src/app/server.js:ro \
		--expose 3000 \
		--env-file txt-xodbox.env \
		--user 1000 \
		node:alpine node /usr/src/app/server.js

update: pull stop start
