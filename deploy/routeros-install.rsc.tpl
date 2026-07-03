# MikroTik WireGuard Easy installer
# Generated file. Review before import.

:local lanAddress "__LAN_ADDRESS__"
:local lanSubnet "__LAN_SUBNET__"
:local disk "__DISK__"
:local uiPort "__UI_PORT__"
:local appPassword "__APP_PASSWORD__"
:local sshPublicKeyFile "wg-easy-id_ed25519.pub"

:local containerBridge "containers"
:local containerSubnet "172.17.0.0/24"
:local routerContainerIp "172.17.0.1"
:local appContainerIp "172.17.0.2"
:local appVeth "veth-wg-easy"
:local containerName "mikrotik-wg-easy"
:local dataDir "__DATA_DIR__"
:local rootDir ($disk . "/images/wg-easy")

__IMAGE_PREFLIGHT__

/interface/bridge
:if ([:len [find where name=$containerBridge]] = 0) do={
  add name=$containerBridge comment="container bridge"
}

/interface/veth
:if ([:len [find where name=$appVeth]] = 0) do={
  add name=$appVeth address=($appContainerIp . "/24") gateway=$routerContainerIp
}

/ip/address
:if ([:len [find where interface=$containerBridge and address=($routerContainerIp . "/24")]] = 0) do={
  add address=($routerContainerIp . "/24") interface=$containerBridge comment="container gateway"
}

/interface/bridge/port
:if ([:len [find where bridge=$containerBridge and interface=$appVeth]] = 0) do={
  add bridge=$containerBridge interface=$appVeth
}

/ip/firewall/nat
:if ([:len [find where comment="wg-easy containers outbound"]] = 0) do={
  add chain=srcnat action=masquerade src-address=$containerSubnet comment="wg-easy containers outbound"
}
:if ([:len [find where comment="wg-easy ui lan only"]] = 0) do={
  add chain=dstnat action=dst-nat protocol=tcp dst-address=$lanAddress dst-port=$uiPort src-address=$lanSubnet to-addresses=$appContainerIp to-ports=8080 comment="wg-easy ui lan only"
}

/user/group
:if ([:len [find where name="wg-easy"]] = 0) do={
  add name=wg-easy policy=ssh,read,write,sensitive,policy,test
}

/user
:if ([:len [find where name="wg-easy"]] = 0) do={
  add name=wg-easy group=wg-easy disabled=no
}

/user/ssh-keys
:if ([:len [/file/find where name=$sshPublicKeyFile]] > 0) do={
  :if ([:len [find where user="wg-easy"]] = 0) do={
    import user=wg-easy public-key-file=$sshPublicKeyFile
  }
}

/container/envs
:foreach i in=[find where list="ENV_WG_EASY"] do={ remove $i }
add list=ENV_WG_EASY key=APP_PASSWORD value=$appPassword
add list=ENV_WG_EASY key=ROS_HOST value=$routerContainerIp
add list=ENV_WG_EASY key=ROS_USER value="wg-easy"
add list=ENV_WG_EASY key=ROS_SSH_KEY value="/data/id_ed25519"
add list=ENV_WG_EASY key=APP_TRUST_PROXY_HEADERS value="0"
add list=ENV_WG_EASY key=WG_ALLOWED_IPS value="0.0.0.0/0"
add list=ENV_WG_EASY key=WG_CLIENT_CIDR value="10.8.0.0/24"
add list=ENV_WG_EASY key=WG_ROUTER_ADDRESS value="10.8.0.1/24"

/container/mounts
:if ([:len [find where list="MOUNT_WG_EASY" and dst="/data"]] = 0) do={
  add list=MOUNT_WG_EASY src=$dataDir dst=/data
} else={
  set [find where list="MOUNT_WG_EASY" and dst="/data"] src=$dataDir
}

/container
:if ([:len [find where name=$containerName]] = 0) do={
  add __CONTAINER_ADD_SOURCE__ name=$containerName interface=$appVeth root-dir=$rootDir mountlists=MOUNT_WG_EASY envlist=ENV_WG_EASY start-on-boot=yes logging=yes
}
start [find where name=$containerName]

:put ("MikroTik WireGuard Easy install script finished. Open http://" . $lanAddress . ":" . $uiPort)
:put ("Check /user/ssh-keys/print where user=wg-easy. If key is missing, upload wg-easy-id_ed25519.pub and re-import this script.")
