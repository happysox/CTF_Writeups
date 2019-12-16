int main(){
    for (int i = 0; i < 10; i++){
        printf("@[%d] : \t %02hhx\n", i, 7 << ((i - 1U) & 0x1f));
    }
    return 0;
}
