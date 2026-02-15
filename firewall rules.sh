!/bin/bash

# Flush old rules

iptables -F
# --- Admins: Full Access ---

iptables -A INPUT -s 10.10.0.16/31 -j ACCEPT


# --- Developers: Everything except SSH ---

iptables -A INPUT -s 10.10.0.32/30 -p tcp --dport 22 -j DROP    # Block SSH first

iptables -A INPUT -s 10.10.0.32/30 -j ACCEPT                    # Then allow all else


# --- Guests: Only HTTP/HTTPS ---

iptables -A INPUT -s 10.10.0.64/29 -p tcp --dport 80 -j ACCEPT

iptables -A INPUT -s 10.10.0.64/29 -p tcp --dport 443 -j ACCEPT
echo "Firewall rules applied."

