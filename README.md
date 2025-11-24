# CTF Write-ups Website

Sitio web estático generado con **MkDocs Material** que muestra write-ups de CTFs desde Obsidian.

## 🚀 Características

- ✅ **Syntax highlighting** para bash, python, php, sql, javascript, etc.
- ✅ **Tema oscuro** por defecto (perfecto para hacking)
- ✅ **Búsqueda en tiempo real**
- ✅ **Lightbox para imágenes** (click para ampliar)
- ✅ **Responsive** (móvil, tablet, desktop)
- ✅ **Sincronización automática** desde repositorio de notas
- ✅ **Deploy automático** en Vercel

## 📁 Estructura del Proyecto

```
ctf-writeups/
├── docs/                  # Contenido del sitio (generado automáticamente)
│   ├── index.md
│   ├── DockerLabs/
│   ├── HackTheBox/
│   └── HackMyVm/
├── scripts/
│   └── sync_notes.py     # Script de sincronización
├── mkdocs.yml            # Configuración de MkDocs
├── requirements.txt      # Dependencias Python
└── vercel.json          # Configuración de Vercel
```

## 🛠️ Instalación Local

### Requisitos
- Python 3.8+
- pip

### Pasos

1. **Instalar dependencias:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Sincronizar notas desde el repositorio de CTFs:**
   ```bash
   python scripts/sync_notes.py
   ```

3. **Ejecutar servidor de desarrollo:**
   ```bash
   mkdocs serve
   ```

4. **Abrir en el navegador:**
   ```
   http://localhost:8000
   ```

## 🌐 Deployment en Vercel

### Primera vez (Setup)

1. **Crear repositorio en GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit: CTF writeups website"
   git branch -M main
   git remote add origin https://github.com/TU-USUARIO/ctf-writeups-web.git
   git push -u origin main
   ```

2. **Conectar con Vercel:**
   - Ve a [vercel.com](https://vercel.com)
   - Haz clic en "Add New Project"
   - Importa tu repositorio de GitHub
   - Vercel detectará automáticamente la configuración de `vercel.json`
   - Haz clic en "Deploy"

### Workflow Automático

Una vez configurado, el workflow es súper simple:

1. **Editas tus notas en Obsidian** (en el repo de CTFs)
2. **Haces commit y push en el repo de CTFs:**
   ```bash
   git add .
   git commit -m "Added new CTF writeup"
   git push
   ```

3. **Haces commit y push en este repo (ctf-writeups):**
   ```bash
   git add .
   git commit -m "Update writeups"
   git push
   ```

4. **Vercel detecta el cambio y despliega automáticamente** ✨

> **Nota:** El script `sync_notes.py` se ejecuta automáticamente en cada deploy de Vercel, así que las notas siempre estarán actualizadas.

## 🔄 Sincronización Manual

Si quieres sincronizar las notas manualmente antes de hacer commit:

```bash
python scripts/sync_notes.py
```

Esto:
- Copia las notas desde `d:\NOTAS-PROGRA-V1\NOTAS-PROGRA\CiberSeguridad\CTFs`
- Convierte sintaxis de Obsidian a MkDocs:
  - `![[imagen.png]]` → `![](../assets/imagen.png)`
  - Callouts `> [!todo]` → Admonitions de MkDocs
- Organiza por categorías (DockerLabs, HackTheBox, HackMyVm)

## 🎨 Personalización

### Cambiar colores del tema

Edita `mkdocs.yml`:

```yaml
theme:
  palette:
    - scheme: slate
      primary: deep purple  # Cambia este color
      accent: purple        # Cambia este color
```

Colores disponibles: `red`, `pink`, `purple`, `deep purple`, `indigo`, `blue`, `light blue`, `cyan`, `teal`, `green`, `light green`, `lime`, `yellow`, `amber`, `orange`, `deep orange`

### Agregar más categorías

1. Crea la carpeta en el repo de CTFs
2. Edita `scripts/sync_notes.py` y agrega la categoría a la lista:
   ```python
   categories = ["DockerLabs", "HackTheBox", "HackMyVm", "TuNuevaCategoria"]
   ```

## 📝 Build para Producción

```bash
python scripts/sync_notes.py
mkdocs build
```

Esto genera el sitio estático en la carpeta `site/`.

## 🐛 Troubleshooting

### Las imágenes no se ven
- Verifica que la carpeta `assets` existe en cada categoría
- Verifica que las rutas en los archivos .md sean correctas

### El build falla en Vercel
- Verifica que `requirements.txt` tenga todas las dependencias
- Revisa los logs de Vercel para ver el error específico

### Los callouts no se ven bien
- Asegúrate de que estás usando la sintaxis correcta de Obsidian: `> [!tipo]`
- Tipos soportados: `note`, `tip`, `warning`, `danger`, `todo`, etc.

## 📚 Recursos

- [MkDocs Material Documentation](https://squidfunk.github.io/mkdocs-material/)
- [Vercel Documentation](https://vercel.com/docs)
- [Markdown Guide](https://www.markdownguide.org/)

## 📄 Licencia

Este proyecto es de uso personal para documentar write-ups de CTFs.
