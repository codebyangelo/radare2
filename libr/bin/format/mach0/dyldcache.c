/* radare - LGPL - Copyright 2010-2026 - nibble, pancake  */

#include <r_types.h>
#include <r_util.h>
#include "dyldcache.h"

static bool r_bin_dyldcache_init(struct r_bin_dyldcache_obj_t* bin) {
	int len = r_buf_fread_at (bin->b, 0, (ut8*)&bin->hdr, "16c4i7l", 1);
	if (len == -1) {
		r_sys_perror ("read (cache_header)");
		return false;
	}
	bin->nlibs = bin->hdr.numlibs;
	return true;
}

static int r_bin_dyldcache_apply_patch(RBuffer* buf, ut32 data, ut64 offset) {
	const ut64 bufsz = r_buf_size (buf);
	if (bufsz < sizeof (data) || offset > bufsz - sizeof (data)) {
		return -1;
	}
	return r_buf_write_at (buf, offset, (ut8 *)&data, sizeof (data));
}

#define NZ_OFFSET(x, y, z) do { \
	if (linkedit_offset > 0 && (x) >= linkedit_offset) { \
		r_bin_dyldcache_apply_patch (dbuf, (ut32)((x) - linkedit_offset), cmd_off + r_offsetof (y, z)); \
	} \
} while (0)

// make it public in util/buf.c ?
static ut64 r_buf_read64le(RBuffer *buf, ut64 off) {
	ut8 data[8] = {0};
	r_buf_read_at (buf, off, data, 8);
	return r_read_le64 (data);
}

static char *r_buf_read_string(RBuffer *buf, ut64 addr, int len) {
	if (len < 1) {
		return NULL;
	}
	ut8 *data = calloc (1, len);
	if (data) {
		r_buf_read_at (buf, addr, data, len);
		data[len - 1] = 0;
		return (char *)data;
	}
	return NULL;
}

/* TODO: Needs more testing and ERROR HANDLING */
R_API struct r_bin_dyldcache_lib_t *r_bin_dyldcache_extract(struct r_bin_dyldcache_obj_t* bin, int idx, int *nlib) {
	ut64 liboff, linkedit_offset;
	ut64 dyld_vmbase;
	ut32 addend = 0;
	struct r_bin_dyldcache_lib_t *ret = NULL;
	struct dyld_cache_image_info* image_infos = NULL;
	struct mach_header mh;
	ut64 cmdptr;
	ut32 cmd;
	RBuffer* dbuf = NULL;
	char *libname = NULL;

	if (!bin) {
		return NULL;
	}
	if (bin->size < 1) {
		R_LOG_WARN ("Empty file? (%s)", r_str_getf (bin->file));
		return NULL;
	}
	if (bin->nlibs < 0 || idx < 0 || idx >= bin->nlibs) {
		return NULL;
	}
	const ut64 binsize = (ut64)bin->size;
	*nlib = bin->nlibs;
	ret = R_NEW0 (struct r_bin_dyldcache_lib_t);
	if (bin->hdr.startaddr > binsize || bin->hdr.baseaddroff > binsize || sizeof (ut64) > binsize - bin->hdr.baseaddroff) {
		R_LOG_ERROR ("corrupted dyldcache");
		goto ret_err;
	}
	const ut64 sz = (ut64)bin->nlibs * sizeof (struct dyld_cache_image_info);
	if (sz > binsize - bin->hdr.startaddr) {
		goto ret_err;
	}
	image_infos = malloc (sz);
	if (!image_infos) {
		goto ret_err;
	}
	const st64 nr = r_buf_read_at (bin->b, bin->hdr.startaddr, (ut8 *)image_infos, sz);
	if (nr < 0 || (ut64)nr != sz) {
		goto ret_err;
	}
	dyld_vmbase = r_buf_read64le (bin->b, bin->hdr.baseaddroff);
	if (image_infos[idx].address < dyld_vmbase) {
		R_LOG_ERROR ("Corrupted file");
		goto ret_err;
	}
	liboff = image_infos[idx].address - dyld_vmbase;
	if (liboff > binsize) {
		R_LOG_ERROR ("Corrupted file");
		goto ret_err;
	}
	ret->offset = liboff;
	const ut32 pfo = image_infos[idx].pathFileOffset;
	if (pfo >= binsize) {
		R_LOG_ERROR ("corrupted file: pathFileOffset >= bin->size (%u)", pfo);
		goto ret_err;
	}
	libname = r_buf_read_string (bin->b, pfo, 64);
	if (!libname) {
		R_LOG_ERROR ("failed to read library name");
		goto ret_err;
	}
	/* Locate lib hdr in cache */
	int r = r_buf_read_at (bin->b, liboff, (ut8 *)&mh, sizeof (mh));
	if (r != sizeof (mh)) {
		goto ret_err;
	}
	/* Check it is mach-o */
	if (mh.magic != MH_MAGIC && mh.magic != MH_MAGIC_64) {
		if (mh.magic == 0xbebafeca) {
			R_LOG_WARN ("FAT Binary");
		}
		R_LOG_WARN ("Not mach-o");
		goto ret_err;
	}
	addend = mh.magic == MH_MAGIC? sizeof (struct mach_header) : sizeof (struct mach_header_64);
	/* Write mach-o hdr */
	dbuf = r_buf_new ();
	if (!dbuf) {
		R_LOG_ERROR ("failed to create buffer");
		goto ret_err;
	}
	if (!r_buf_append_buf_slice (dbuf, bin->b, liboff, addend)) {
		goto dbuf_err;
	}
	cmdptr = liboff + addend;
	/* Write load commands */
	for (cmd = 0; cmd < mh.ncmds; cmd++) {
		struct load_command lc;
		int r = r_buf_read_at (bin->b, cmdptr, (ut8 *)&lc, sizeof (lc));
		if (r != sizeof (lc)) {
			goto dbuf_err;
		}
		if (lc.cmdsize < sizeof (lc) || cmdptr > (ut64)bin->size || lc.cmdsize > (ut64)bin->size - cmdptr) {
			goto dbuf_err;
		}
		if (!r_buf_append_buf_slice (dbuf, bin->b, cmdptr, lc.cmdsize)) {
			goto dbuf_err;
		}
		cmdptr += lc.cmdsize;
	}
	cmdptr = liboff + addend;
	/* Write segments */
	for (cmd = linkedit_offset = 0; cmd < mh.ncmds; cmd++) {
		struct load_command lc;
		int r = r_buf_read_at (bin->b, cmdptr, (ut8 *)&lc, sizeof (lc));
		if (r != sizeof (lc)) {
			goto dbuf_err;
		}
		const ut64 cmd_off = cmdptr - liboff;
		switch (lc.cmd) {
		case LC_SEGMENT:
			{
			/* Write segment and patch offset */
			struct segment_command seg;
			if (lc.cmdsize < sizeof (seg)) {
				goto dbuf_err;
			}
			r = r_buf_read_at (bin->b, cmdptr, (ut8 *)&seg, sizeof (seg));
			if (r != sizeof (seg)) {
				goto dbuf_err;
			}
			if (seg.fileoff > (ut64)bin->size || seg.filesize > (ut64)bin->size - seg.fileoff) {
				R_LOG_ERROR ("malformed dyldcache");
				goto dbuf_err;
			}
			const ut64 seg_new_fileoff = r_buf_size (dbuf);
			if (seg_new_fileoff > UT32_MAX) {
				goto dbuf_err;
			}
			if (seg.filesize > 0 && !r_buf_append_buf_slice (dbuf, bin->b, seg.fileoff, seg.filesize)) {
				goto dbuf_err;
			}
			r_bin_dyldcache_apply_patch (dbuf, (ut32)seg_new_fileoff,
				cmd_off + r_offsetof (struct segment_command, fileoff));
			/* Patch section offsets */
			const ut64 sect_offset = seg.fileoff > seg_new_fileoff? seg.fileoff - seg_new_fileoff: 0;
			if (!strncmp (seg.segname, "__LINKEDIT", sizeof (seg.segname))) {
				linkedit_offset = sect_offset;
			}
			const ut64 expected_cmdsize = sizeof (struct segment_command) + (ut64)seg.nsects * sizeof (struct section);
			if (seg.nsects > 0 && lc.cmdsize >= expected_cmdsize) {
				ut32 nsect;
				for (nsect = 0; nsect < seg.nsects; nsect++) {
					struct section sect;
					const ut64 sect_cmd_off = sizeof (struct segment_command) + (ut64)nsect * sizeof (struct section);
					if (r_buf_read_at (bin->b, cmdptr + sect_cmd_off, (ut8 *)&sect, sizeof (sect)) != sizeof (sect)) {
						break;
					}
					if (sect_offset > 0 && sect.offset >= sect_offset) {
						r_bin_dyldcache_apply_patch (dbuf, sect.offset - (ut32)sect_offset,
							cmd_off + sect_cmd_off + r_offsetof (struct section, offset));
					}
				}
			}
			}
			break;
		case LC_SYMTAB:
			{
			struct symtab_command st;
			if (lc.cmdsize < sizeof (st)) {
				goto dbuf_err;
			}
			r = r_buf_read_at (bin->b, cmdptr, (ut8 *)&st, sizeof (st));
			if (r != sizeof (st)) {
				goto dbuf_err;
			}
			NZ_OFFSET (st.symoff, struct symtab_command, symoff);
			NZ_OFFSET (st.stroff, struct symtab_command, stroff);
			}
			break;
		case LC_DYSYMTAB:
			{
			struct dysymtab_command st;
			if (lc.cmdsize < sizeof (st)) {
				goto dbuf_err;
			}
			r = r_buf_read_at (bin->b, cmdptr, (ut8 *)&st, sizeof (st));
			if (r != sizeof (st)) {
				goto dbuf_err;
			}
			NZ_OFFSET (st.tocoff, struct dysymtab_command, tocoff);
			NZ_OFFSET (st.modtaboff, struct dysymtab_command, modtaboff);
			NZ_OFFSET (st.extrefsymoff, struct dysymtab_command, extrefsymoff);
			NZ_OFFSET (st.indirectsymoff, struct dysymtab_command, indirectsymoff);
			NZ_OFFSET (st.extreloff, struct dysymtab_command, extreloff);
			NZ_OFFSET (st.locreloff, struct dysymtab_command, locreloff);
			}
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY:
			{
			struct dyld_info_command st;
			if (lc.cmdsize < sizeof (st)) {
				goto dbuf_err;
			}
			r = r_buf_read_at (bin->b, cmdptr, (ut8 *)&st, sizeof (st));
			if (r != sizeof (st)) {
				goto dbuf_err;
			}
			NZ_OFFSET (st.rebase_off, struct dyld_info_command, rebase_off);
			NZ_OFFSET (st.bind_off, struct dyld_info_command, bind_off);
			NZ_OFFSET (st.weak_bind_off, struct dyld_info_command, weak_bind_off);
			NZ_OFFSET (st.lazy_bind_off, struct dyld_info_command, lazy_bind_off);
			NZ_OFFSET (st.export_off, struct dyld_info_command, export_off);
			}
			break;
		}
		cmdptr += lc.cmdsize;
	}
	/* Fill r_bin_dyldcache_lib_t ret */
	ret->b = dbuf;
	r_str_ncpy (ret->path, libname, sizeof (ret->path));
	ret->size = r_buf_size (dbuf);
	free (libname);
	free (image_infos);
	return ret;

dbuf_err:
	r_unref (dbuf);
ret_err:
	free (libname);
	free (image_infos);
	free (ret);
	return NULL;
}

R_API void* r_bin_dyldcache_free(struct r_bin_dyldcache_obj_t* bin) {
	if (!bin) {
		return NULL;
	}
	r_unref (bin->b);
	free (bin);
	return NULL;
}

void r_bin_dydlcache_get_libname(struct r_bin_dyldcache_lib_t *lib, char **libname) {
	const char *last_slash = r_str_rchr (lib->path, NULL, '/');
	*libname = (char *)(last_slash? last_slash + 1: lib->path);
}

struct r_bin_dyldcache_obj_t* r_bin_dyldcache_new(const char* file) {
	struct r_bin_dyldcache_obj_t *bin = R_NEW0 (struct r_bin_dyldcache_obj_t);
	bin->file = file;
	size_t binsz;
	ut8 *buf = (ut8 *)r_file_slurp (file, &binsz);
	bin->size = binsz;
	if (!buf) {
		return r_bin_dyldcache_free (bin);
	}
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free (buf);
		return r_bin_dyldcache_free (bin);
	}
	free (buf);
	if (!r_bin_dyldcache_init (bin)) {
		return r_bin_dyldcache_free (bin);
	}
	return bin;
}

R_API struct r_bin_dyldcache_obj_t* r_bin_dyldcache_from_bytes_new(const ut8* buf, ut64 size) {
	struct r_bin_dyldcache_obj_t *bin = R_NEW0 (struct r_bin_dyldcache_obj_t);
	if (!buf) {
		return r_bin_dyldcache_free (bin);
	}
	bin->b = r_buf_new ();
	if (!bin->b || !r_buf_set_bytes (bin->b, buf, size)) {
		return r_bin_dyldcache_free (bin);
	}
	if (!r_bin_dyldcache_init (bin)) {
		return r_bin_dyldcache_free (bin);
	}
	bin->size = size;
	return bin;
}
