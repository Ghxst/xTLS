.PHONY: test

test:
	go run ./tools/genoverlay
	go run -overlay=overlay/overlay.json ./test
