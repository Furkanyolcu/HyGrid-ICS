##
## FIX SORUN-5: Zeek ICMP ve UDP Flood Logging (SADELEŞTİRİLMİŞ)
## ==============================================================
## UDP ve ICMP bağlantılarının (flood) Zeek kapatılmadan önce
## conn.log dosyasına hızlıca yazılabilmesi için timeout
## süreleri düşürüldü.
##

redef udp_inactivity_timeout = 5 secs;
redef tcp_inactivity_timeout = 60 secs;
redef icmp_inactivity_timeout = 5 secs;
