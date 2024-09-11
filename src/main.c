#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <linux/limits.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <uthash.h>
#include <sys/stat.h>
#include <errno.h>

#define HASH_SIZE (SHA256_DIGEST_LENGTH * 2 + 1)
#define BUFFER_SIZE 32768

typedef struct {
    char filename[PATH_MAX];
    UT_hash_handle hh;
} filename_t;

typedef struct {
    char hash[HASH_SIZE];
    filename_t *filenames;
    UT_hash_handle hh;
} hash_entry_t;

void hash_file(const char *filename, char *hash) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error opening file %s: %s\n", filename, strerror(errno));
        return;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned char hash_raw[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(mdctx, md, NULL);
    unsigned char *buffer = malloc(BUFFER_SIZE);
    size_t bytesRead = 0;

    if (!buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        return;
    }

    while((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytesRead);
    }

    EVP_DigestFinal_ex(mdctx, hash_raw, &hash_len);

    for(unsigned int i = 0; i < hash_len; i++) {
        sprintf(hash + (i * 2), "%02x", hash_raw[i]);
    }
    hash[hash_len * 2] = '\0';

    free(buffer);
    fclose(file);
    EVP_MD_CTX_free(mdctx);
}

void process_file(const char *filepath, hash_entry_t **hash_table) {
    char hash[HASH_SIZE];
    hash_file(filepath, hash);

    hash_entry_t *hash_entry;
    HASH_FIND_STR(*hash_table, hash, hash_entry);
    
    if (hash_entry == NULL) {
        hash_entry = calloc(1, sizeof(hash_entry_t));
        if (!hash_entry) {
            fprintf(stderr, "Memory allocation failed\n");
            return;
        }
        strncpy(hash_entry->hash, hash, HASH_SIZE - 1);
        hash_entry->hash[HASH_SIZE - 1] = '\0';
        HASH_ADD_STR(*hash_table, hash, hash_entry);
    }

    filename_t *filename_entry = calloc(1, sizeof(filename_t));
    if (!filename_entry) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    strncpy(filename_entry->filename, filepath, PATH_MAX - 1);
    filename_entry->filename[PATH_MAX - 1] = '\0';
    HASH_ADD_STR(hash_entry->filenames, filename, filename_entry);
}


void traverse_directory(const char *dir_path, hash_entry_t **hash_table) {
    DIR *dir;
    struct dirent *ent;
    char fullpath[PATH_MAX];
    struct stat file_stat;

    if ((dir = opendir(dir_path)) == NULL) {
        fprintf(stderr, "Could not open directory %s: %s\n", dir_path, strerror(errno));
        return;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }

        snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_path, ent->d_name);

        if (lstat(fullpath, &file_stat) == 0) {
            if (S_ISDIR(file_stat.st_mode)) {
                traverse_directory(fullpath, hash_table);
            } else if (S_ISREG(file_stat.st_mode)) {
                process_file(fullpath, hash_table);
            }
        } else {
            fprintf(stderr, "Error stating file %s: %s\n", fullpath, strerror(errno));
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    char cwd[PATH_MAX];
    const char *start_path = (argc > 1) ? argv[1] : ".";

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        fprintf(stderr, "getcwd() error: %s\n", strerror(errno));
        return 1;
    }

    hash_entry_t *hash_table = NULL;

    traverse_directory(start_path, &hash_table);

    // results
    hash_entry_t *hash_entry, *tmp;
    HASH_ITER(hh, hash_table, hash_entry, tmp) {
        filename_t *filename_entry, *tmp_filename;
        int file_count = HASH_COUNT(hash_entry->filenames);
        
        if (file_count > 1) {
            char truncated_hash[7];
            strncpy(truncated_hash, hash_entry->hash, 6);
            truncated_hash[6] = '\0';
            printf("Duplicate files (hash: %s):\n", truncated_hash);
            HASH_ITER(hh, hash_entry->filenames, filename_entry, tmp_filename) {
                char *relative_path = filename_entry->filename;
                if (strncmp(filename_entry->filename, cwd, strlen(cwd)) == 0) {
                    relative_path += strlen(cwd);
                    if (*relative_path == '/') {
                        relative_path++;
                    }
                    printf("  ./%s\n", relative_path);
                } else {
                    printf("  %s\n", filename_entry->filename);
                }
            }
            printf("\n");
        }
    }

    return 0;
}
