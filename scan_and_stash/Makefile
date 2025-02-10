TOOL_SRC=scan_stash_tool.c
TOOL_BIN=scan_stash_tool
TOOL_ACE_SRC=scan_stash_ace_tool.c
TOOL_ACE_BIN=scan_stash_ace_tool

CC=./select-compiler

all: tool ace-tool

tool: $(TOOL_BIN)

ace-tool: $(TOOL_ACE_BIN)

$(TOOL_BIN): $(TOOL_SRC)
	$(CC) -Wall $(TOOL_SRC) -o $(TOOL_BIN) -lprocstat -lutil

$(TOOL_ACE_BIN): $(TOOL_ACE_SRC)
	$(CC) -Wall $(TOOL_ACE_SRC) -o $(TOOL_ACE_BIN)

clean-tool:
	rm -f $(TOOL_BIN)

clean-ace-tool:
	rm -f $(TOOL_ACE_BIN)

clean:
	make clean-tool
	make clean-ace-tool
