
unsigned int elf_hash(const char *_name)
{
	const unsigned char *name = (const unsigned char *)_name;
	unsigned h = 0, g;

	while (*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000;
		h ^= g;
		h ^= g >> 24;
	}
	return h;
}