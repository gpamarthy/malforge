.PHONY: build-sandbox test-sandbox clean

build-sandbox:
	docker build -t malforge-sandbox -f Dockerfile.sandbox .

test-sandbox: build-sandbox
	docker run --rm malforge-sandbox

clean:
	rm -rf *.cs *.exe *.dll *.vba *.ps1 *.csproj *.js sc.bin scripts/__pycache__
