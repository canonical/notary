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
notary: $(ARTIFACT_FOLDER)/$(NOTARY_ARTIFACT_NAME)
	@echo "Built notary"

.PHONY: config-files
config-files: $(ARTIFACT_FOLDER)/$(NOTARY_CONFIG_FILE) $(ARTIFACT_FOLDER)/$(NOTARY_TLS_CERT) $(ARTIFACT_FOLDER)/$(NOTARY_TLS_KEY)
	@echo "Created config files"

.PHONY: rock
rock: $(ARTIFACT_FOLDER)/$(ROCK_ARTIFACT_NAME)
	@echo "Built notary rock"

.PHONY: deploy
deploy: $(ARTIFACT_FOLDER)/$(ROCK_ARTIFACT_NAME)
	@if [ "$$(lxc list 2> /dev/null | grep notary > /dev/null; echo $$?)" = 1 ]; then \
		echo "creating new notary VM instance in LXD"; \
		lxc launch ubuntu:24.04 --vm notary; \
	fi
	@echo "waiting for the VM to start"
	@while [ "$$(lxc exec notary -- echo "hello" &> /dev/null; echo $$?)" = 0 ]; do sleep 2; done
	sleep 10
	lxc exec notary -- snap install docker --classic
	lxc exec notary -- snap install rockcraft --classic
	@if [ "$$(lxc exec notary -- docker ps 2> /dev/null | grep jaeger > /dev/null; echo $$?)" = 1 ]; then \
		echo "creating and running jaeger in Docker"; \
		lxc exec notary -- docker run --rm --name jaeger \
			--network host \
  			-p 16686:16686 \ # HTTP, /api/v3/*, OTLP-based JSON over HTTP
		    -p 4317:4317   \ # gRPC, ExportTraceServiceRequest, OTLP Protobuf
		    -p 4318:4318   \ # HTTP, /v1/traces, OTLP Protobuf or OTLP JSON
		    -p 5778:5778   \ # HTTP, /sampling, sampling.proto_via Protobuf-to-JSON mapping_
		    -p 9411:9411   \ # HTTP, /api/v2/spans, Zipkin v2 JSON or Protobuf
		    jaegertracing/jaeger:2.6.0; \
		sleep 10; \
	fi

	lxc file push $(ARTIFACT_FOLDER)/$(ROCK_ARTIFACT_NAME) notary/root/$(ROCK_ARTIFACT_NAME)
	lxc file push $(ARTIFACT_FOLDER)/$(NOTARY_CONFIG_FILE) notary/root/config/$(NOTARY_CONFIG_FILE)
	lxc file push $(ARTIFACT_FOLDER)/$(NOTARY_TLS_CERT) notary/root/config/$(NOTARY_TLS_CERT)
	lxc file push $(ARTIFACT_FOLDER)/$(NOTARY_TLS_KEY) notary/root/config/$(NOTARY_TLS_KEY)
	@if [ "$$(lxc exec notary -- docker ps 2> /dev/null | grep notary > /dev/null; echo $$?)" = 0 ]; then \
		echo "removing old notary container"; \
		lxc exec notary -- docker stop notary; \
		lxc exec notary -- docker rm notary; \
	fi

	lxc exec notary -- rockcraft.skopeo --insecure-policy copy oci-archive:notary.rock docker-daemon:notary:latest
	# lxc exec notary -- docker run -d \
	# 	--name notary \
	# 	-v /root:/config/webuicfg.yaml \
	# 	--network host \
	# 	notary:latest --verbose
	# @echo "You can access notary at $$(lxc info nms | grep enp5s0 -A 15 | grep inet: | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'):2111"

# hotswap: artifacts/webconsole examples/config/webuicfg.yaml
# 	@echo "make: replacing nms binary with new binary"
# 	lxc file push artifacts/notary notary/root/
# 	lxc exec notary -- docker cp ./notary nms:/bin/notary
# 	lxc exec notary -- docker exec notary pebble restart notary

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
	@echo 'key_path: "key.pem"'         >> $@;\
     echo 'cert_path: "cert.pem"'       >> $@;\
     echo 'db_path: "notary.db"'        >> $@;\
     echo 'port: 2111'                  >> $@;\
	 echo 'pebble_notifications: true'  >> $@;\
	 echo 'logging:'                    >> $@;\
	 echo '  system:'                   >> $@;\
	 echo '    level: "debug"'          >> $@;\
	 echo '    output: "file"'          >> $@;\
	 echo '    path: "notary.log"'      >> $@;\
	 echo 'tracing:'                    >> $@;\
	 echo '  enabled: true'             >> $@;\
	 echo '  service_name: "notary"'    >> $@;\
	 echo '  endpoint: "127.0.0.1:4317"'>> $@;\
	 echo '  sampling_rate: "100%"'     >> $@

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
