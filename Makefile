ARTIFACT_FOLDER := artifacts

NOTARY_BACKEND_FILES := $(shell find internal/ cmd/ -type f)
NOTARY_UI_FILES := $(shell find ui/src/ -type f) ui/package.json ui/package-lock.json

NOTARY_ARTIFACT_NAME := notary
NOTARY_CONFIG_FILE := config.yaml
NOTARY_TLS_CERT := cert.pem
NOTARY_TLS_KEY := key.pem
ROCK_ARTIFACT_NAME := notary.rock

$(shell mkdir -p $(ARTIFACT_FOLDER))

.PHONY: notary
notary: $(ARTIFACT_FOLDER)/$(NOTARY_ARTIFACT_NAME) $(ARTIFACT_FOLDER)/$(NOTARY_CONFIG_FILE) $(ARTIFACT_FOLDER)/$(NOTARY_TLS_CERT) $(ARTIFACT_FOLDER)/$(NOTARY_TLS_KEY)
	@echo "Built notary"

.PHONY: config-files
config-files: $(ARTIFACT_FOLDER)/$(NOTARY_CONFIG_FILE) $(ARTIFACT_FOLDER)/$(NOTARY_TLS_CERT) $(ARTIFACT_FOLDER)/$(NOTARY_TLS_KEY)
	@echo "Created config files"

.PHONY: rock
rock: $(ARTIFACT_FOLDER)/$(ROCK_ARTIFACT_NAME)
	@echo "Built notary rock"

.PHONY: hotswap
hotswap:
	@echo "make: replacing notary binary with new binary"
	lxc file push artifacts/notary notary/root/
	lxc exec notary -- docker cp ./notary notary:/bin/notary
	lxc exec notary -- docker exec notary pebble restart notary

deploy: $(ARTIFACT_FOLDER)/$(ROCK_ARTIFACT_NAME)
	@# Start notary container if it's not available
	@if [ "$$(lxc list 2> /dev/null | grep notary > /dev/null; echo $$?)" = 1 ]; then \
		echo "creating new notary VM instance in LXD"; \
		lxc launch ubuntu:24.04 --vm notary; \
		\
		echo "waiting for the VM to start"; \
		while [ "$$(lxc exec notary -- echo "hello" &> /dev/null; echo $$?)" = 0 ]; do sleep 2; done ;\
	    sleep 10; \
		\
		echo "installing docker and rockcraft"; \
		lxc exec notary -- snap install docker; \
	    lxc exec notary -- snap install rockcraft --classic ;\
		\
		echo "pushing config files"; \
		lxc file push $(ARTIFACT_FOLDER)/$(ROCK_ARTIFACT_NAME) notary/root/$(ROCK_ARTIFACT_NAME); \
		lxc file push $(ARTIFACT_FOLDER)/$(NOTARY_CONFIG_FILE) notary/root/$(NOTARY_CONFIG_FILE); \
		lxc file push $(ARTIFACT_FOLDER)/$(NOTARY_TLS_CERT) notary/root/$(NOTARY_TLS_CERT); \
		lxc file push $(ARTIFACT_FOLDER)/$(NOTARY_TLS_KEY) notary/root/$(NOTARY_TLS_KEY); \
	fi

	@# Remove the old notary if it was still there
	@if [ "$$(lxc exec notary -- docker ps -a 2> /dev/null | grep notary > /dev/null; echo $$?)" = 0 ]; then \
		echo "removing old notary container"; \
		lxc exec notary -- docker stop notary; \
		lxc exec notary -- docker rm notary; \
	fi

	lxc exec notary -- rockcraft.skopeo --insecure-policy copy oci-archive:$(ROCK_ARTIFACT_NAME) docker-daemon:notary:latest
	lxc exec notary -- docker run -d \
		--name notary \
		-v /root:/config \
		--network host \
		-p 2111:2111 \
		notary:latest --args notary -config /config/config.yaml;
	@echo "You can access notary at $$(lxc info notary | grep enp5s0 -A 15 | grep inet: | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'):2111"

logs:
	lxc exec notary -- docker logs notary --tail 20

clean:
	rm -rf $(ARTIFACT_FOLDER)
	-lxc stop notary
	-lxc delete notary

clean-vm:
	-lxc stop notary
	-lxc delete notary

$(ARTIFACT_FOLDER)/$(NOTARY_CONFIG_FILE):
	@echo 'key_path: "artifacts/key.pem"'      >> $@;\
     echo 'cert_path: "artifacts/cert.pem"'    >> $@;\
     echo 'db_path: "artifacts/notary.db"'     >> $@;\
     echo 'port: 2111'                         >> $@;\
	 echo 'pebble_notifications: false'        >> $@;\
	 echo 'logging:'                           >> $@;\
	 echo '  system:'                          >> $@;\
	 echo '    level: "debug"'                 >> $@;\
	 echo '    output: "artifacts/notary.log"' >> $@;\
	 echo 'encryption_backend: {}'             >> $@;\

$(ARTIFACT_FOLDER)/$(NOTARY_TLS_CERT) $(ARTIFACT_FOLDER)/$(NOTARY_TLS_KEY):
	openssl req -newkey rsa:2048 -nodes -keyout $(ARTIFACT_FOLDER)/$(NOTARY_TLS_KEY) -x509 -days 1 -out $(ARTIFACT_FOLDER)/$(NOTARY_TLS_CERT) -subj "/CN=example.com"

$(ARTIFACT_FOLDER)/$(NOTARY_CONFIG_FILE):

ui/out: $(NOTARY_UI_FILES)
	@npm install --prefix ui && npm run build --prefix ui

$(ARTIFACT_FOLDER)/$(NOTARY_ARTIFACT_NAME): $(NOTARY_BACKEND_FILES) ui/out
	go build -o $(ARTIFACT_FOLDER)/$(NOTARY_ARTIFACT_NAME) ./cmd/notary/main.go

$(ARTIFACT_FOLDER)/$(ROCK_ARTIFACT_NAME): $(ARTIFACT_FOLDER)/$(NOTARY_ARTIFACT_NAME) rockcraft.yaml
	-rockcraft pack
	mv $$(ls | grep *.rock) $@;
