# Run hadoop in a container
#
#

# Old version of debian in order to install java 8 from sources
FROM debian:stretch-slim

LABEL maintainer "Iñaki Garitano <igaritano@garitano.org>"

# Set environment variables
ENV DEBIAN_FRONTEND noninteractive
ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64
ENV USER hadoop
ENV HOME /home/$USER
ENV HADOOP_HOME /usr/share/hadoop
ENV PATH $PATH:$HADOOP_HOME/bin
ENV PATH $PATH:$HADOOP_HOME/sbin

# Install hadoop requirements
RUN apt-get update \
 && apt-get install -qqy \
    sudo \
    openssh-server \
    openssh-client \
    rsync \
    openjdk-8-jdk \
    --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Add hadoop user
RUN groupadd -g 1000 $USER \
 && useradd -u 1000 -g 1000 -G sudo --create-home --home-dir $HOME $USER \
 && chown -R $USER:$USER $HOME

# Change hadoop user password to hadoop
RUN cp /etc/shadow /etc/shadow_backup \
 ;  sed -r 's/(^'$USER':)[^:]*(.*$)/\1$6$PkJj\/RZx$kXe\/pZQjK23cFv1KSPGtIv3FXhygaCNatgQyPa7CK2UCI0oEOGS8.DQF679xLQnaG7RsDT6HrEyJM1SPGkHWA0\2/g' /etc/shadow_backup > /etc/shadow \
 ;  rm /etc/shadow_backup \
 ;  chmod o+r /etc/shadow

# Copy hadoop into container
COPY /resources/software/hadoop-3.2.0.tar.gz /usr/share/

# Extract hadoop
RUN cd /usr/share \
  ; tar xzf hadoop-3.2.0.tar.gz \
  ; ln -s /usr/share/hadoop-3.2.0 /usr/share/hadoop

# Copy hadoop configuration files
COPY /resources/configfiles /usr/share/hadoop/etc/hadoop/

# Change hadoop owner and group
RUN chown -R $USER:$USER /usr/share/hadoop-3.2.0 \
  ; chown -R $USER:$USER /usr/share/hadoop \
  ; mkdir /var/log/hadoop \
  ; chown -R $USER:$USER /var/log/hadoop \
  ; chmod 775 /var/log/hadoop

# Set host SSH keys
RUN ssh-keygen -q -N "" -t dsa -f /etc/ssh/ssh_host_dsa_key \
  ; yes | ssh-keygen -q -N "" -t rsa -f /etc/ssh/ssh_host_rsa_key

# Set hadoop SSH keys
WORKDIR $HOME

USER $USER

RUN ssh-keygen -q -N "" -t rsa -f $HOME/.ssh/id_rsa \
  ; cp $HOME/.ssh/id_rsa.pub $HOME/.ssh/authorized_keys

# Set and start SSH server for hadoop namenode format
USER root

RUN mkdir /run/sshd \
  ; /usr/sbin/sshd

# Format hadoop namenode
USER $USER

RUN $HADOOP_HOME/bin/hdfs namenode -format

ENTRYPOINT [ "/bin/bash" ]

# Remember hadoop has two services, hdfs and yarn
# hdfs needs to format the store folder, this is performed during container creation

# After running hadoop container and before starting hdfs and yarn SSH server needs to be started
# docker exec -d -u 0 container_name /usr/sbin/sshd

# After running SSH server start hdfs and yarn
# start-dfs.sh
# start-yarn.sh

# Connect to 9870 port in order to get the web page
