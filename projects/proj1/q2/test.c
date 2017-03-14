#include <stdio.h>
#include <stdlib.h>

int main(int argc, char * argv[]) {
	char msg[1024];
	int n_write, n_read;

	int8_t size;
	char str[1024];
	sprintf(str, "%c\nffas dfsfasdfasdfa dfasdfasdf dfasd fasdfasdf vasdf asdf asdfa sdfasdfasdf asdgertewrfq ret ewrqwwrqe rtwert eqrtqe tqrwtqw wqrrwe hnklfn skjdfbiwerhq ikjasdf aksdfbqij w fbjsdmfansk dlfasjkdsdfj basdkfabksdfb dsfdjkf kjdsf bksis fhaksjdfba jskdfqwhjef testing end here.", 255);

	FILE *fpt_write = fopen("text.txt", "w");
	n_write = fwrite(str, 1, 1024, fpt_write);
	printf("write %d\n", n_write);
	fclose(fpt_write);

	FILE *fpt = fopen("text.txt", "r");
	fread(&size, 1, 1, fpt);
	printf("%d %u\n", size, size);
	n_read = fread(msg, 1, size, fpt);
	printf("read %d\n",n_read);
	puts(msg);
	fclose(fpt);
}