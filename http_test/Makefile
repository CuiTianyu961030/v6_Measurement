CC = gcc
CCC = g++
CFLAGS = -Wall -g -fPIC  -D_GNU_SOURCE -D_BSD_SOURCE=1 -D__BSD_SOURCE=1 -D__USE_MISC=1 -D__FAVOR_BSD=1
INC = -I./inc/

LDFLAGS = -L./lib/
LIBS =-lMESA_htable -lMESA_handle_logger -lMESA_prof_load  -lmagellan_logger 
OBJ = http_test.o log_writer.o recorder.o 
TARGET = http_test.so

.c.o:
	$(CC) -c $(CFLAGS) $< $(INC)
.cpp.o:
	$(CCC) -c $(CFLAGS) $(INC) $<

$(TARGET): $(OBJ)
	$(CCC) -o $@ $(OBJ) $(LDFLAGS) $(LIBS) -shared

clean:
	rm -rf $(OBJ) $(TARGET)

.PHONY:clean
