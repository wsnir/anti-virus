#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
} virus;

typedef struct link {
    struct link *nextVirus;
    virus *vir;
} link;

typedef struct fun_desc {
    char *name;
    void (*fun)();
} fun_desc;

int isBigEndian = 0;
link *vir_list = NULL;
FILE* outfile = NULL;
char filename[256];

void PrintHex(unsigned char* buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        fprintf(outfile, "%02X ", buffer[i]);
    }
    fprintf(outfile, "\n\n");
}

unsigned short set_endian(unsigned char* bytes) {
    if (isBigEndian) {
        return (bytes[0] << 8) | bytes[1];
    }
    return (bytes[1] << 8) | bytes[0];
}

virus* readVirus(FILE* file) {
    virus* v = (virus*)malloc(sizeof(virus));
    if (fread(v, 18, 1, file) != 1) {
        free(v);
        return NULL;
    }

    v->SigSize = set_endian((unsigned char*)&v->SigSize);
    v->sig = (unsigned char*)malloc(v->SigSize);

    if (fread(v->sig, v->SigSize, 1, file) != 1) {
        free(v->sig);
        free(v);
        return NULL;
    }
    return v;
}

void printVirus(virus* virus, FILE* output) {
    fprintf(output, "Virus name: %s\n", virus->virusName);
    fprintf(output, "Virus size: %d\n", virus->SigSize);
    fprintf(output, "Signature:\n");
    PrintHex(virus->sig, virus->SigSize);
}

void list_print(link *virus_list, FILE* output) {
    if (virus_list != NULL) {
        list_print(virus_list->nextVirus, output);
        printVirus(virus_list->vir, output);
    }
    fflush(output);
}

link* list_append(link* virus_list, virus* data) {
    link *newLink = (link*)malloc(sizeof(link));
    newLink->vir = data;
    newLink->nextVirus = virus_list;
    return newLink;
}

void list_free(link *virus_list) {
    link *current = virus_list;
    while (current != NULL) {
        link *next = current->nextVirus;
        free(current->vir->sig);
        free(current->vir);
        free(current);
        current = next;
    }
}

void load_signatures() {
    printf("Enter signature file name: ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = '\0';

    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    char magic[4];
    if (fread(magic, 1, 4, file) != 4 || (strncmp(magic, "VIRL", 4) != 0 && strncmp(magic, "VIRB", 4) != 0)) {
        perror("Invalid magic number");
        fclose(file);
        return;
    }

    isBigEndian = (strncmp(magic, "VIRB", 4) == 0);
    virus* v;
    while ((v = readVirus(file)) != NULL) {
        vir_list = list_append(vir_list, v);
    }

    fclose(file);
    printf("\n");
}

void detect_virus(char *buffer, unsigned int size, link *virus_list) {
    link *current = virus_list;
    while (current != NULL) {
        for (unsigned int i = 0; i < size - current->vir->SigSize + 1; i++) {
            if (memcmp(buffer + i, current->vir->sig, current->vir->SigSize) == 0) {
                printf("Starting byte: %d\n", i);
                printf("Virus name: %s\n", current->vir->virusName);
                printf("Virus signature size: %d\n\n", current->vir->SigSize);
            }
        }
        current = current->nextVirus;
    }
}

void neutralize_virus(char *fileName, int signatureOffset) {
    FILE *file = fopen(fileName, "r+b");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    if (fseek(file, signatureOffset, SEEK_SET) != 0) {
        perror("Error seeking in file");
        fclose(file);
        return;
    }

    unsigned char RET = 0xC3;
    if (fwrite(&RET, sizeof(RET), 1, file) != 1) {
        perror("Error writing to file");
    }
    fclose(file);
}

void neutralize(char *buffer, unsigned int size, link *virus_list){
    link *current = virus_list;
    while (current != NULL) {
        for (unsigned int i = 0; i < size - current->vir->SigSize + 1; i++) {
            if (memcmp(buffer + i, current->vir->sig, current->vir->SigSize) == 0) {
                neutralize_virus(filename, i);
                printf("Neutralized virus at byte %d\n\n", i);
            }
        }
        current = current->nextVirus;
    }
}

void process_file(void (*process_func)(char *, unsigned int, link *)) {
    printf("Enter suspected file name: ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = '\0';

    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    const int BUFFER_SIZE = 10240;
    char buffer[BUFFER_SIZE];

    size_t bytesRead = fread(buffer, 1, BUFFER_SIZE, file);
    fclose(file);
    if (bytesRead > 0) {
        printf("\n");
        process_func(buffer, bytesRead, vir_list);
    }
}

void print_signatures() {
    list_print(vir_list, outfile);
}

void detect_viruses() {
    process_file(detect_virus);
}

void fix_file() {
    process_file(neutralize);
}

void quit() {
    list_free(vir_list);
    if (outfile != stdout){
        fclose(outfile);
    }
    exit(0);
}

fun_desc menu[] = {
    {"Load signatures", load_signatures},
    {"Print signatures", print_signatures},
    {"Detect viruses", detect_viruses},
    {"Fix file", fix_file},
    {"Quit", quit},
    {NULL, NULL}
};

int main(int argc, char **argv) {
    int bound = sizeof(menu) / sizeof(menu[0]) - 1;
    char choice[10];
    int option;
    outfile = stdout;

    if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'o') {
        outfile = fopen(argv[1] + 2, "w+b");
        if (outfile == NULL) {
            perror("Error opening output file");
            printf("Using stdout\n");
            outfile = stdout;
        }
    }

    while (1) {
        printf("Select operation from the following menu:\n");
        for (int i = 0; i < bound; i++) {
            printf("%d) %s\n", i + 1, menu[i].name);
        }
        printf("\nOption: ");

        if (fgets(choice, sizeof(choice), stdin) == NULL) {
            quit();
        }

        if (sscanf(choice, "%d", &option) != 1) {
            printf("Invalid input\n\n");
            continue;
        }

        if (option >= 1 && option <= bound) {
            menu[option - 1].fun();
        } else {
            printf("Invalid option\n\n");
        }
    }

    return 0;
}