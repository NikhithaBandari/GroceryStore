import checksumdir

# Specify the directory path you want to check
directory_path = 'C:/Users/nikhi/Desktop/GroceryStore'

# Calculate the checksum (hash) of the directory using the default MD5 algorithm
directory_checksum = checksumdir.dirhash(directory_path)

# Display the calculated checksum
print(f"Checksum of the directory: {directory_checksum}")
