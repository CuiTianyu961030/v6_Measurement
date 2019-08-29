#include <stdio.h>
#include <iostream>
#include <string.h>
//#include <std>
using namespace std;

int main()
{
    FILE *fp,*fp1;
    fp = fopen("/home/guoyu/ssl_log/ssl_json", "r");
    char s[2048];
    int i,ch,n=0,l=0;
    cout<<'[';
    while(!feof(fp))
    {   
        fgets(s, 2048, fp);
	n++;
    }
    fclose(fp);
    fp = fopen("/home/guoyu/ssl_log/ssl_json", "r");   
    while(l != n-1)
    {
	fgets(s, 2048, fp);
	i=strlen(s);
        if (s[i-1]=='\n')
	{
	    s[i-1]=',';
            printf("%s",s); 
	}
        l++;
	//else printf("%s",s);
    }
    fgets(s, 2048, fp);
    i=strlen(s);
    s[i-1]='\0';
    printf("%s",s);
    //fgets(s, 2048, fp);
    //printf("%s\n", s);
    cout<<']';
    return 0;
}
