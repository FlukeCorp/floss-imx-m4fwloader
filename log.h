#pragma once

extern int verbose;

#define LogVerbose(...)          \
    do {                         \
        if (verbose)             \
            printf(__VA_ARGS__); \
    } while (0)
#define LogError(...) printf(__VA_ARGS__)
