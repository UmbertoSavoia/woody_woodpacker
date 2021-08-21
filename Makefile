TARGET = woody_woodpacker

CC = gcc
CFLAGS = -Werror -Wall -Wextra -g

AS = nasm
ASFLAGS64 = -f elf64
ASFLAGS32 = -f elf32
ASFLAGSPE = -f win64

RM = rm -f

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
PAYLOADELF64 = payload/inject64.s
PAYLOADELF32 = payload/inject32.s
PAYLOADEPE64 = payload/injectPE64.s

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) $^ -o $(TARGET)
	$(AS) $(ASFLAGS64) $(PAYLOADELF64) -o payload/inject64.o
	$(AS) $(ASFLAGS32) $(PAYLOADELF32) -o payload/inject32.o
	$(AS) $(ASFLAGSPE) $(PAYLOADEPE64) -o payload/injectPE64.obj

bonus : all

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJS)
	$(RM) payload/inject64.o
	$(RM) payload/inject32.o
	$(RM) payload/injectPE64.obj
	$(RM) woody

fclean: clean
	$(RM) $(TARGET)

re: fclean all