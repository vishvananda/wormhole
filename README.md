# wormhole #

## A namespaced activated tunneling proxy ##

Wormhole is an activated proxy daemon and an associated cli. It allows you to
securely connect ports together on different physical machines or containers.
This allows for interesting things like connecting to things running on
localhost inside the container namespace or creating on-demand services that
start when you connect to them.

## But Why? ##

Containers have mostly been copying networking and configuration from servers,
but containers provide radical  new options that haven't been explored. They
gives us the opportunity to move a whole bunch of complicated distributed
systems problems like orchestration, service discovery, configuration
management, and security down into the communication layer. If we can
accomplish this, we achieve something quite amazing: Standard containers become
truly reusable.

This isn't intended to be a production solution for container relationships,
consider it an exploration into moving more down into the communication layer.
If I can create an application container that talks to a single port to get
a secure connection to the database, I've made a bunch of things easier. I
don't have to configure the application to talk to an ip address. I don't
have to set a secure password on the database server. I can move the database
without breaking the application. I can put another database in play and
start load balancing between them.

Yes it is computationally expensive to proxy these connections, but if the
proxy layer gains some more features like load-balancing and traffic analysis
then it is simply replacing existing proxies instead of adding an additional
layer to most workloads.

Some people may feel that is overloading localhost to proxy connections this
way; localhost traffic should always be local. That is a fair point and it
would be completely reasonable to do this on some other known ip address. The
one advantage of the localhost approach is almost every application is
configured to listen on localhost out of the box so it makes the build
process super simple.

## Other Tools ##

Most of what wormhole does can be accomplished with existing tools like socat
and iproute2. Wormhole was created because the process is complex and fragile.
It is much easier to have a single binary that does it all for you.

## Getting Started ##

To get started you will need to:

 a) Create a secret key

    sudo mkdir -p /etc/wormhole
    cat /dev/urandom | tr -dc '0-9a-zA-Z' | head -c 32 | sudo tee /etc/wormhole/key.secret
    sudo chmod 600 /etc/wormhole/key.secret

 b) Run the daemon as root

    sudo ./wormholed

The wormhole cli communicates with the deamon over port 9999. To verify it is working:

    ./wormhole ping

## Examples ##

### Proxy to the mysql in a local container ###

This requires a local install of mysql-client (ubuntu: apt-get install mysql-client).

    mysql=`docker run -d wormhole/mysql`
    ./wormhole create url :3306 docker-ns tail docker-ns $mysql
    mysql -u root -h 127.0.0.1

### Connect a local wordpress container to a local mysql container ###

    app=`docker run -d wormhole/wordpress`
    mysql=`docker run -d wormhole/mysql`
    ./wormhole create url :3306 docker-ns $app tail docker-ns $mysql

### Create a local port that does the above on connection  ###

    ./wormhole create url :80 trigger docker-run wormhole/wordpress \
               child url :3306 tail docker-run wormhole/mysql

### Create a local port to talk to a remote mysql ###

The remote server must be running wormhole with the same key.secret

    mysql=`docker -H myserver run -d wormhole/mysql`
    ./wormhole create url :3306 remote myserver tail docker-ns $mysql

### Create a local port to talk to a remote mysql over an ipsec tunnel ###

    mysql=`docker -H myserver run -d wormhole/mysql`
    ./wormhole create url :3306 tunnel myserver tail docker-ns $mysql

### Create a local port that runs a remote mysql server on connection ###

If the image has not been downloaded on 'myserver' then the initial connection will timeout.

    ./wormhole create url :3306 trigger tunnel myserver trigger docker-run wormhole/mysql

### Create a local port that runs wordpress locally followed by the above  ###

    ./wormhole create url :80 trigger docker-run wormhole/wordpress \
               child url :3306 tunnel myserver tail docker-run wormhole/mysql

### Forget all this proxy stuff and just give me an ipsec tunnel  ###

This command outputs a local and remote ip for the tunnel.

    ./wormhole tunnel-create myserver

Tunnels are not deleted when wormholed is closed. To delete the tunnel:

    ./wormhole tunnel-delete myserver

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
