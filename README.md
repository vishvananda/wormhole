# wormhole #

### A smart proxy that connects docker containers ###

Wormhole is a namespace-aware socket-activated tunneling proxy. It allows you
to securely connect ports together on different physical machines inside
docker containers. This allows for interesting things like connecting services
running on localhost inside the container namespace or creating on-demand
services that start when you connect to them.

## But Why? ##

Containers give us the opportunity to move a whole bunch of complicated
distributed systems problems (orchestration, service discovery, configuration
management, and security) into the communication layer. They have the
potential to finally give us [truly standard components](https://medium.com/@vishvananda/standard-components-not-standard-containers-c30567f23da6)

This isn't intended to be a production solution for container relationships.
Consider it an exploration of the above value. If you can create an
application container that talks to a single port to get a secure connection
to the database, many things get simpler. You don't have to configure the
application with the proper address. You don't have to set a secure password
for the database server. You can move the database without breaking the
application. You can add a second database and start load balancing.

Most importantly, standardizing the communication layer means that containers
are trivially sharable. Everyone who needs a mysql database container can
use the same one. No configuration of the container is necessary, you can just
drop it in and start using it.

Yes it is computationally more expensive to proxy connections, but consider:

1. It is possible to accomplish many of the same things with sdn instead
   of proxying
2. This proxy could replace the proxies that many services already use
   for load balancing or ssl termination.

Some people may feel that is inappropriate to proxy localhost connections this
way, that localhost traffic should always be local. The above principles can
be accomplished by using another well-known ip address. The one advantage of
the localhost approach is almost every application is configured to listen on
localhost out of the box so it makes container builds very easy.

## Examples ##

### Legend for diagrams ###
![ex-legend](https://cloud.githubusercontent.com/assets/142222/4346902/25bd6e18-411f-11e4-8f0c-b2a4cfa2208f.png)

### Proxy to the mysql in a local container ###
![ex-01](https://cloud.githubusercontent.com/assets/142222/4346904/2a7fb85c-411f-11e4-9637-0e7bbd5fe506.png)

    mysql=`docker run -d wormhole/mysql`
    ./wormhole create url :3306 docker-ns tail docker-ns $mysql
    mysql -u root -h 127.0.0.1

This requires a local install of mysql-client (ubuntu: apt-get install mysql-client).

### Connect a local wp container to a local mysql container ###
![ex-02](https://cloud.githubusercontent.com/assets/142222/4346903/2a750024-411f-11e4-9aa4-818bfe05b0e1.png)

    app=`docker run -d wormhole/wordpress`
    mysql=`docker run -d wormhole/mysql`
    ./wormhole create url :3306 docker-ns $app tail docker-ns $mysql

### Create a local port that does the above on connection  ###
![ex-03](https://cloud.githubusercontent.com/assets/142222/4346905/2a8f1446-411f-11e4-97e3-41060c6d2432.png)

    ./wormhole create url :80 trigger docker-run wormhole/wordpress \
               child url :3306 trigger docker-run wormhole/mysql

### Create a local port to talk to a remote mysql ###
![ex-04](https://cloud.githubusercontent.com/assets/142222/4346908/2a96b5f2-411f-11e4-9e36-1921a8a3cbda.png)

    mysql=`docker -H myserver run -d wormhole/mysql`
    ./wormhole create url :3306 remote myserver tail docker-ns $mysql

The remote server must be running wormhole with the same key.secret

### Do the above over an ipsec tunnel ###
![ex-05](https://cloud.githubusercontent.com/assets/142222/4346907/2a96b868-411f-11e4-8e86-7bb2f9ff8e15.png)

    mysql=`docker -H myserver run -d wormhole/mysql`
    ./wormhole create url :3306 tunnel myserver trigger docker-ns $mysql

### Create a local port that runs a remote mysql on connection ###
![ex-06](https://cloud.githubusercontent.com/assets/142222/4346909/2a96d406-411f-11e4-9461-3308404704ba.png)

    ./wormhole create url :3306 trigger tunnel myserver trigger docker-run wormhole/mysql

If the image has not been downloaded on 'myserver' then the initial
connection will timeout.

### Create a local port that runs wp followed by the above  ###
![ex-07](https://cloud.githubusercontent.com/assets/142222/4346906/2a949a4c-411f-11e4-9784-44ba18ca7a1d.png)

    ./wormhole create url :80 trigger docker-run wormhole/wordpress \
               child url :3306 tunnel myserver trigger docker-run wormhole/mysql

### Forget all this proxy stuff and make an ipsec tunnel  ###
![ex-08](https://cloud.githubusercontent.com/assets/142222/4346910/2a973aa4-411f-11e4-8ff3-b4a7c6e4efce.png)


    ./wormhole tunnel-create myserver

This command outputs a local and remote ip for the tunnel. Tunnels are
not deleted when wormholed is closed. To delete the tunnel:

    ./wormhole tunnel-delete myserver

## Getting Started ##

To get started you will need to:

 a) Create a secret key

    sudo mkdir -p /etc/wormhole
    cat /dev/urandom | tr -dc '0-9a-zA-Z' | head -c 32 | sudo tee /etc/wormhole/key.secret
    sudo chmod 600 /etc/wormhole/key.secret

 b) Run the daemon as root

    sudo ./wormholed

The wormhole cli communicates with the daemon over port 9999. To verify it
is working:

    ./wormhole ping

## Local Build and Test ##

Getting the source code:

    go get github.com/vishvananda/wormhole

Building the binaries (will install go dependencies via go get):

    make

Testing dependencies:

    docker is required for functional tests

Unit Tests (functional tests use sudo):

    make test-unit

Functional tests (requires root):

    make test-functional # or sudo -E go test -v functional_test.go

## Alternative Tools ##

Most of what wormhole does can be accomplished by hacking together various
tools like socat and iproute2.

## Future Work ##

Wormhole could be extended to support unix socket proxying. It would also be
interesting to allow proxies from one type of socket to another a la socat.

Wormhole discovers existing tunnels when it starts, but it doesn't attempt
to cleanup if it finds a partial tunnel. This option could be added.

Namespace support should be upstreamed to kubernetes/proxy so we don't have
to maintain a fork.

Commands for list and tunnel-list should be added.

Wormhole could grow support for load balancing.

Traffic analysis and reporting could be added to the proxy layer.
