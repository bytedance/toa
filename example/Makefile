

# PORT := 8192



run_server_v4: server_v4
	./server_v4 8192

run_server_v6: server_v6
	./server_v6 8193

run_client_tcp_opt_v4: client_tcp_opt_v4
	./client_tcp_opt_v4 127.0.0.1 8192 10.0.0.1 1 

run_client_tcp_opt_v6: client_tcp_opt_v6
	./client_tcp_opt_v6 ::1 8193 fdbd::1 1



server_v4: server_v4.cpp util.h util.cpp
	g++ -o $@ $^ -pthread

server_v6: server_v6.cpp util.h util.cpp
	g++ -o $@ $^ -pthread

client_tcp_opt_v4: client_tcp_opt_v4.c
	gcc -o $@ $^

client_tcp_opt_v6: client_tcp_opt_v6.c
	gcc -o $@ $^
