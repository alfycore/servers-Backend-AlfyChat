package servers

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alfychat/servers/internal/platform"
)

const maxUploadSize = 50 * 1024 * 1024

// Extension dérivée du type déclaré, jamais du nom d'origine.
var fileExtByMime = map[string]string{
	"image/png": "png", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp", "image/avif": "avif",
	"video/mp4": "mp4", "video/webm": "webm", "video/ogg": "ogv",
	"audio/mpeg": "mp3", "audio/ogg": "ogg", "audio/webm": "weba", "audio/wav": "wav", "audio/mp4": "m4a",
	"application/pdf": "pdf", "text/plain": "txt",
}

// Types tels que les sert Express (mime 1.x).
var mimeByExt = map[string]string{
	"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
	"avif": "application/octet-stream", "mp4": "video/mp4", "webm": "video/webm", "ogv": "video/ogg",
	"mp3": "audio/mpeg", "ogg": "audio/ogg", "weba": "audio/webm", "wav": "audio/wav", "m4a": "audio/mp4", "pdf": "application/pdf",
}

var inlineExts = map[string]bool{"png": true, "jpg": true, "jpeg": true, "gif": true, "webp": true, "avif": true,
	"mp4": true, "webm": true, "ogv": true, "mp3": true, "ogg": true, "weba": true, "wav": true, "m4a": true, "pdf": true}

func uploadsDir() string {
	p, _ := filepath.Abs(platform.Env("UPLOADS_DIR", "./uploads/server-files"))
	return p
}

func latin1(s string) string {
	r := make([]rune, len(s))
	for i := 0; i < len(s); i++ {
		r[i] = rune(s[i])
	}
	return string(r)
}

// uploadFile : POST /servers/:serverId/files (multer .single('file')). Les images vont en base, le reste sur disque.
func (h *handlers) uploadFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID := r.PathValue("serverId")
	ct := r.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(ct); err != nil || !strings.HasPrefix(mt, "multipart/") {
		platform.Error(w, 400, "Aucun fichier fourni")
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		h.srv.ServeError(w, r, 500)
		return
	}
	var (
		stored, origName, mimetype string
		size                       int64
		have                       bool
	)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			h.srv.ServeError(w, r, 500)
			return
		}
		_, params, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		rawName, isFile := params["filename"]
		if !isFile {
			_, _ = io.Copy(io.Discard, io.LimitReader(part, 1<<20))
			continue
		}
		if part.FormName() != "file" || have {
			h.srv.ServeError(w, r, 500)
			return
		}
		mimetype = part.Header.Get("Content-Type")
		if mimetype == "" {
			mimetype = "text/plain"
		}
		ext, ok := fileExtByMime[mimetype]
		if !ok {
			h.srv.ServeError(w, r, 500)
			return
		}
		data, err := io.ReadAll(io.LimitReader(part, maxUploadSize+1))
		if err != nil || len(data) > maxUploadSize {
			h.srv.ServeError(w, r, 500)
			return
		}
		stored = newID() + "." + ext
		origName, size, have = latin1(rawName), int64(len(data)), true
		if strings.HasPrefix(mimetype, "image/") {
			_, err = h.db.Exec(ctx, "INSERT INTO server_files (filename, server_id, original_name, mime_type, size, data) VALUES (?, ?, ?, ?, ?, ?)",
				stored, serverID, jsSlice(origName, 255), mimetype, size, data)
		} else {
			if err = os.MkdirAll(uploadsDir(), 0o755); err == nil {
				err = os.WriteFile(filepath.Join(uploadsDir(), stored), data, 0o644)
			}
		}
		if err != nil {
			fail(w, "Erreur enregistrement fichier:", err)
			return
		}
	}
	if !have {
		platform.Error(w, 400, "Aucun fichier fourni")
		return
	}
	platform.JSON(w, 201, platform.O("id", newID(), "url", "/files/"+stored, "originalName", origName, "mimeType", mimetype, "size", size))
}

type keepLastModified struct {
	http.ResponseWriter
	modTime time.Time
}

func (k *keepLastModified) WriteHeader(status int) {
	if status == http.StatusNotModified && k.Header().Get("Last-Modified") == "" {
		k.Header().Set("Last-Modified", k.modTime.UTC().Format(http.TimeFormat))
	}
	k.ResponseWriter.WriteHeader(status)
}

// serveFile : GET /servers/:serverId/files/:filename — base d'abord (images), disque ensuite.
func (h *handlers) serveFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filename := path.Base(r.PathValue("filename"))
	root := uploadsDir()
	fp := filepath.Join(root, filename)
	if !strings.HasPrefix(fp, root+string(filepath.Separator)) {
		forbidden(w, "Accès refusé")
		return
	}

	var (
		content  io.ReadSeeker
		modTime  time.Time
		size     int64
		dbMime   string
		fromDisk bool
	)
	var (
		dbData    []byte
		dbCreated time.Time
	)
	err := h.db.QueryRowContext(ctx, "SELECT mime_type, data, created_at FROM server_files WHERE filename = ?", filename).Scan(&dbMime, &dbData, &dbCreated)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.srv.ServeError(w, r, 500)
		return
	}
	if err == nil {
		content, size, modTime = bytes.NewReader(dbData), int64(len(dbData)), dbCreated
	} else {
		fi, err := os.Stat(fp)
		if err != nil || fi.IsDir() {
			platform.Error(w, 404, "Fichier non trouvé")
			return
		}
		f, err := os.Open(fp)
		if err != nil {
			h.srv.ServeError(w, r, 500)
			return
		}
		defer f.Close()
		content, size, modTime, fromDisk = f, fi.Size(), fi.ModTime(), true
	}

	hd := w.Header()
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(filename), "."))
	ct := "application/octet-stream"
	if inlineExts[ext] {
		if v, ok := mimeByExt[ext]; ok {
			ct = v
		}
		if !fromDisk && dbMime != "" && ct != "application/octet-stream" {
			ct = dbMime
		}
	} else {
		hd.Set("Content-Disposition", "attachment")
	}
	hd.Set("Content-Type", ct)
	hd.Set("Cache-Control", "public, max-age=0")
	hd.Set("ETag", fmt.Sprintf(`W/"%x-%x"`, size, modTime.UnixMilli()))
	if rangeVerdict(r.Header.Get("Range"), size) == rangeIgnore {
		r.Header.Del("Range")
	} else if rangeVerdict(r.Header.Get("Range"), size) == rangeUnsatisfiable {
		hd.Set("Content-Range", "bytes */"+strconv.FormatInt(size, 10))
		// send garde Content-Type, Cache-Control et Accept-Ranges ; res.json ne remplace pas un Content-Type déjà posé.
		hd.Del("ETag")
		hd.Del("Content-Disposition")
		hd.Set("Accept-Ranges", "bytes")
		hd.Set("Content-Type", ct+"; charset=utf-8")
		body := []byte(`{"error":"Internal server error"}`)
		hd.Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(500)
		_, _ = w.Write(body)
		return
	}
	http.ServeContent(&keepLastModified{ResponseWriter: w, modTime: modTime}, r, filename, modTime, content)
}

type rangeResult int

const (
	rangeServe rangeResult = iota
	rangeIgnore
	rangeUnsatisfiable
)

// rangeVerdict reproduit range-parser + send.
func rangeVerdict(header string, size int64) rangeResult {
	if header == "" {
		return rangeServe
	}
	idx := strings.Index(header, "=")
	if idx == -1 || header[:idx] != "bytes" {
		return rangeIgnore
	}
	n := 0
	for _, spec := range strings.Split(header[idx+1:], ",") {
		parts := strings.SplitN(spec, "-", 2)
		if len(parts) != 2 {
			return rangeIgnore
		}
		start, e1 := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		end, e2 := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		switch {
		case e1 != nil && e2 != nil && parts[0] == "" && parts[1] == "":
			continue
		case e1 != nil:
			start, end = size-end, size-1
		case e2 != nil:
			end = size - 1
		}
		if end > size-1 {
			end = size - 1
		}
		if (e1 != nil && e2 != nil) || start > end || start < 0 {
			continue
		}
		n++
	}
	switch {
	case n == 0:
		return rangeUnsatisfiable
	case n == 1:
		return rangeServe
	}
	return rangeIgnore
}
