TARGET = woody_woodpacker

CC = gcc
CFLAGS = -Werror -Wall -Wextra

AS = nasm
ASFLAGS = -f elf64

RM = rm -f

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
PAYLOAD = payload/inject.s

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) $^ -o $(TARGET)
	$(AS) $(ASFLAGS) $(PAYLOAD) -o payload/inject64.o

bonus : all

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJS)
	$(RM) payload/inject64.o
	$(RM) payload/inject32.o
	$(RM) woody

fclean: clean
	$(RM) $(TARGET)