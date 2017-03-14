#include <stdio.h>
#include <stdlib.h>

int dog(int i, int j, int k) {
	int t = i + k;
	char *newbuf = malloc(4);
	t = t + 4;
	t = t -j;
	return t;
}

void cat(char *buffer) {
	int i[2];
	i[1] = 5;
	i[0] = dog(1, 2, i[1]);
}

int main() {
	char buf[8];
	cat(buf);
	return 0;
}