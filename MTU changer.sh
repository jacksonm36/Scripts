#!/bin/bash

echo "🔧 Enforcing MTU inheritance (mtu=1) for all VMs and LXCs..."

# VMs
for vmid in $(qm list | awk 'NR>1 {print $1}'); do
    echo "🖥️ Checking VM $vmid..."
    for net in $(qm config $vmid | grep -oP '^net\d+'); do
        config=$(qm config $vmid | grep "^$net:" | cut -d ':' -f2- | xargs)
        if [[ -z "$config" ]]; then
            echo "⚠️ Skipping $net on VM $vmid — empty config"
            continue
        fi
        if [[ $config == *mtu=1* ]]; then
            echo "✅ $net already set to mtu=1"
        elif [[ $config == *mtu=* ]]; then
            newconfig=$(echo "$config" | sed "s/mtu=[^,]*/mtu=1/")
            echo "🔄 Correcting $net: $newconfig"
            qm set $vmid --$net "$newconfig"
        else
            newconfig="$config,mtu=1"
            echo "➕ Adding mtu=1 to $net: $newconfig"
            qm set $vmid --$net "$newconfig"
        fi
    done
done

# LXCs
for lxcid in $(pct list | awk 'NR>1 {print $1}'); do
    echo "📦 Checking LXC $lxcid..."
    for net in $(pct config $lxcid | grep -oP '^net\d+'); do
        config=$(pct config $lxcid | grep "^$net:" | cut -d ':' -f2- | xargs)
        if [[ -z "$config" ]]; then
            echo "⚠️ Skipping $net on LXC $lxcid — empty config"
            continue
        fi
        if [[ $config == *mtu=1* ]]; then
            echo "✅ $net already set to mtu=1"
        elif [[ $config == *mtu=* ]]; then
            newconfig=$(echo "$config" | sed "s/mtu=[^,]*/mtu=1/")
            echo "🔄 Correcting $net: $newconfig"
            pct set $lxcid -$net "$newconfig"
        else
            newconfig="$config,mtu=1"
            echo "➕ Adding mtu=1 to $net: $newconfig"
            pct set $lxcid -$net "$newconfig"
        fi
    done
done

echo "✅ All interfaces now safely inherit MTU from their bridge (mtu=1)."
