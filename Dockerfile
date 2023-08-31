# TODO in the build step download the overmind binary
FROM golang

RUN go install github.com/DarthSim/overmind/v2@latest

FROM python:slim
COPY --from=0 /go/bin/overmind /bin/overmind

WORKDIR feedreader

RUN apt-get update && apt-get install -y tmux htop

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["overmind", "start"]
