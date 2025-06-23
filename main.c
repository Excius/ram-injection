#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define max 500000

int is_process_running(pid_t pid)
{
  char path[256];
  snprintf(path, sizeof(path), "/proc/%d/status", pid);
  FILE *file = fopen(path, "r");
  if (!file)
  {
    return 0; // Process is not running
  }
  fclose(file);
  return 1; // Process is running
}

// attaching the process
void attach_the_process(pid_t pid)
{
  if (!is_process_running(pid))
  {
    fprintf(stderr, "Error: Process with PID %d is not running.\n", pid);
    exit(EXIT_FAILURE);
  }

  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
  {
    perror("ptrace attach faliure");
    exit(1);
  }
  if (waitpid(pid, NULL, 0) == -1)
  {
    perror("waitpid failed after attaching process");
    exit(EXIT_FAILURE);
  }
}

// deataching the process
void deatach_the_process(pid_t pid)
{
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
  {
    perror("ptrace failed to deatach the process");
    exit(1);
  }
  printf("Detached from process %d successfully.\n", pid);
}

// reading the targe value from the address
size_t read_memory(pid_t pid, unsigned long start, unsigned long end,
                   int targetValue, unsigned long *addresses,
                   size_t max_addresses)
{

  // printf("Reading memory from 0x%lx to 0x%lx\n", start, end);

  size_t count = 0;
  for (unsigned long addr = start; addr < end; addr += sizeof(long))
  {
    long data = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (data == -1)
    {
      // perror("ptrace peekdata failed");
      continue; // Skip unreadable addresses
    }

    // Check if the value matches the target
    for (int i = 0; i < sizeof(long); i++)
    {
      int byte_value = (data >> (i * 8)); // Extract each byte
      if (byte_value == targetValue)
      {
        unsigned long exact_address = addr + i;
        printf("Found value %d at address: 0x%lx\n", targetValue,
               exact_address);

        if (count < max_addresses)
        {
          addresses[count++] = exact_address;
        }
        else
        {
          printf("Address storage limit reached.\n");
          return count;
        }
      }
    }
  }

  return count;
}
size_t find_memory_region(pid_t pid, int targetValue, unsigned long *addresses,
                          size_t max_addresses)
{
  char path[256];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);

  FILE *file = fopen(path, "r");
  if (!file)
  {
    perror("fopen");
    deatach_the_process(pid);
    exit(EXIT_FAILURE);
  }

  // printf("Searching memory regions..\n");

  size_t total_matches = 0;
  char line[256];
  unsigned long start, end;

  while (fgets(line, sizeof(line), file))
  {
    if (strstr(line, "rw-p"))
    {
      sscanf(line, "%lx-%lx", &start, &end);

      total_matches +=
          read_memory(pid, start, end, targetValue, addresses + total_matches,
                      max_addresses - total_matches);
      if (total_matches >= max_addresses)
      {
        printf("Maximum number of matches reached.\n");
        break;
      }
    }
  }
  fclose(file);
  deatach_the_process(pid);
  return total_matches;
}

void rescan_memory(pid_t pid, unsigned long *addresses, size_t count,
                   int new_target_value, unsigned long *new_addresses,
                   size_t *new_count)
{
  *new_count = 0;

  printf("Rescanning %zu addresses for value: %d\n", count, new_target_value);

  attach_the_process(pid);

  for (size_t i = 0; i < count; i++)
  {
    unsigned long addr = addresses[i];
    long data = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (data == -1)
    {
      perror("ptrace peekdata failed during rescan");
      continue;
    }

    if ((int)data == new_target_value)
    {
      printf("Found new value %d at address: 0x%lx\n", new_target_value, addr);
      new_addresses[(*new_count)++] = addresses[i];
    }
  }
  deatach_the_process(pid);
}

void edit_memory(pid_t pid, unsigned long address, int newValue)
{
  if (ptrace(PTRACE_POKEDATA, pid, (void *)address, (void *)newValue) == -1)
  {
    perror("ptrace pokedata failed");
    deatach_the_process(pid);
    exit(EXIT_FAILURE);
  }
  printf("Successfully wrote %d to address 0x%lx\n", newValue, address);
}

int main()
{
  pid_t pid;
  int target_value;
  unsigned long addresses[max]; // Storage for matching addresses
  size_t total_matches;
  unsigned long new_addresses[max];
  size_t new_matches;
  int newValue;

  printf("Enter the PID of the target process: ");
  scanf("%d", &pid);

  if (!is_process_running(pid))
  {
    fprintf(stderr, "Error: Process with PID %d is not running.\n", pid);
    return 1;
  }

  attach_the_process(pid);

  printf("Enter the target value to search for: ");
  scanf("%d", &target_value);

  total_matches = find_memory_region(pid, target_value, addresses, max);

  printf("Initial scan complete. Found %zu matching addresses.\n",
         total_matches);

  while (1)
  {
    printf("Enter a new target value to rescan (or -1 to exit): ");
    scanf("%d", &target_value);

    if (target_value == -1)
    {
      printf("Exiting...\n");
      break;
    }

    if (!is_process_running(pid))
    {
      fprintf(stderr, "Error: Process with PID %d is no longer running.\n",
              pid);
      break;
    }

    rescan_memory(pid, addresses, total_matches, target_value, new_addresses,
                  &new_matches);
  }

  printf("Enter a new target value you want to assign: ");
  scanf("%d", &newValue);
  printf("\n");

  attach_the_process(pid);
  for (size_t i = 0; i < new_matches; i++)
  {
    edit_memory(pid, new_addresses[i], newValue);
  }
  deatach_the_process(pid);

  return 0;
}
