all: cpp-grpc-client grpc-wace-client mod-wace
	
clean:
	rm -rf *.la *.o *.lo *.slo *.lo cmake/build/* .libs
mod-wace:
	sudo apxs -Wl -Wc -cia -I../misc/res/ModSecurity-2.9.3/apache2 -I/usr/include/libxml2 -I. -L./cmake/build/ -lgrpc_wace_client mod_wace.c
	sudo systemctl restart httpd
cpp-grpc-client:
	protoc --grpc_out=grpc_wace_client/cpp_client --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` wace.proto
	protoc --cpp_out=grpc_wace_client/cpp_client wace.proto

grpc-wace-client:
	cd cmake/build/ && cmake ../..
	cd cmake/build/ && make
	sudo cp -r cmake/build/libgrpc_wace_client.so /usr/lib64/
	sudo ldconfig
