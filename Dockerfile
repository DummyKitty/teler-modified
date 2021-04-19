FROM golang:1.14.2-alpine3.11 as build

ARG VERSION

LABEL description="Real-time HTTP Intrusion Detection"
LABEL repository="https://github.com/GreyDr34d/teler-modified"
LABEL maintainer="greyDr34d"

WORKDIR /app
COPY ./go.mod .
RUN go env -w GO111MODULE=on
RUN go env -w GOPROXY=https://goproxy.io,direct
RUN go mod download

COPY . .
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk add build-base
RUN gcc -std=c99 -Wall -Werror -fpic -c ./libinjetion_build/libinjection/libinjection_sqli.c -o /usr/lib/libinjection_sqli.o \
    && gcc -std=c99 -Wall -Werror -fpic -c ./libinjetion_build/libinjection/libinjection_xss.c -o /usr/lib/libinjection_xss.o \
    && gcc -std=c99 -Wall -Werror -fpic -c ./libinjetion_build/libinjection/libinjection_html5.c -o /usr/lib/libinjection_html5.o \
    && gcc -dynamiclib -shared -o /usr/lib/libinjection.so /usr/lib/libinjection_sqli.o /usr/lib/libinjection_xss.o /usr/lib/libinjection_html5.o

RUN go build -ldflags "-s -w -X ktbs.dev/teler/common.Version=${VERSION}" \
	-o ./bin/teler ./cmd/teler

FROM alpine:latest

COPY --from=build /app/bin/teler /bin/teler
COPY --from=build /usr/lib/libinjection*.so /usr/lib/

ENV HOME /
ENTRYPOINT ["/bin/teler"]
