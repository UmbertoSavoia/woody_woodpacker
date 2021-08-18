TARGET = woody_woodpacker

CC = gcc
CFLAGS = -Werror -Wall -Wextra

AS = nasm
ASFLAGS64 = -f elf64
ASFLAGS32 = -f elf32

RM = rm -f

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
PAYLOAD64 = payload/inject64.s
PAYLOAD32 = payload/inject32.s

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) $^ -o $(TARGET)
	$(AS) $(ASFLAGS64) $(PAYLOAD64) -o payload/inject64.o
	$(AS) $(ASFLAGS32) $(PAYLOAD32) -o payload/inject32.o

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

re: fclean all