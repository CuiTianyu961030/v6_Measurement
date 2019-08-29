CC = gcc 
CCC = g++ 
CFLAGS = -Wall -g -fPIC  -D_GNU_SOURCE -D_BSD_SOURCE=1 -D__BSD_SOURCE=1 -D__USE_MISC=1 -D__FAVOR_BSD=1
INC = -I./inc

LDFLAGS = -L ./lib/
LIBS =-lMESA_handle_logger   
OBJ = ssl_test.o log_writer.o recorder.o  GetFileSHA1.o
TARGET = ssl_test.so

.c.o:
	$(CC) -c $(CFLAGS) $< $(INC)
.cpp.o:
	$(CCC) -c $(CFLAGS) $(INC) $<
	
all:$(TARGET)

$(TARGET): $(OBJ)
	$(CCC) -o $@ $(OBJ) $(LDFLAGS) $(LIBS) -shared

clean:
	rm -rf $(OBJ) $(TARGET)

.PHONY:clean
