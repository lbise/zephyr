#!/bin/bash
# Creates interfaces and bridges on the host to setup the Zephyr network
set -e

IFACE=( "zeth0" "zeth1" "zeth2" "zeth3")
BRIDGE0="zeth-br0"
BRIDGE1="zeth-br1"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
NETTOOLS=$DIR/../../../../tools/net-tools

usage() {
	echo "$0 up|down"
	echo "Setup the interfaces and bridges required for the routing sample"
	exit
}

if [ "$#" -lt 1 ]; then
	usage
fi

while [ $# -gt 0 ]
do
	case $1 in
		up)
			ACTION=up
			shift
			;;
		down)
			ACTION=down
			shift
			;;
		-h)
			usage
			;;
		-help)
			usage
			;;
		*)
			echo "Unknown option $1"
			usage
			;;
	esac
done

if [ "$ACTION" == up ]; then
	for IF in "${IFACE[@]}"
	do
		echo "${IF}"
		$NETTOOLS/net-setup.sh --config $DIR/${IF}.conf -i $IF start
	done

	# Create bridge between interfaces
	sudo brctl addbr $BRIDGE0
	sudo brctl addif $BRIDGE0 ${IFACE[0]}
	sudo brctl addif $BRIDGE0 ${IFACE[1]}
	sudo ifconfig $BRIDGE0 up

	sudo brctl addbr $BRIDGE1
	sudo brctl addif $BRIDGE1 ${IFACE[2]}
	sudo brctl addif $BRIDGE1 ${IFACE[3]}
	sudo ifconfig $BRIDGE1 up
elif [ "$ACTION" == down ]; then
	for IF in "${IFACE[@]}"
	do
		echo "${IF}"
		$NETTOOLS/net-setup.sh --config $DIR/${IF}.conf -i $IF stop
	done

	sudo ifconfig $BRIDGE0 down
	sudo brctl delbr $BRIDGE0
	sudo ifconfig $BRIDGE1 down
	sudo brctl delbr $BRIDGE1
fi

