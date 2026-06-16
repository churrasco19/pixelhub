const fs = require('fs');
const path = require('path');

/**
 * Generador automático de README.md para PixelHub
 * Este script analiza la estructura del proyecto y genera documentación
 */

const projectRoot = __dirname;

/**
 * Lee recursivamente la estructura de directorios
 * @param {string} dir - Directorio a analizar
 * @param {string} prefix - Prefijo para el árbol
 * @param {boolean} isLast - Indica si es el último elemento
 * @returns {string} Árbol del proyecto formateado
 */
function generateTree(dir, prefix = '', isLast = true) {
  const items = fs.readdirSync(dir).filter(item => !item.startsWith('.'));
  let tree = '';

  items.forEach((item, index) => {
    const itemPath = path.join(dir, item);
    const isDirectory = fs.statSync(itemPath).isDirectory();
    const isLastItem = index === items.length - 1;
    const connector = isLastItem ? '└── ' : '├── ';
    const extension = isLastItem ? '    ' : '│   ';

    if (isDirectory) {
      tree += `${prefix}${connector}${item}/\n`;
      tree += generateTree(itemPath, prefix + extension, isLastItem);
    } else {
      tree += `${prefix}${connector}${item}\n`;
    }
  });

  return tree;
}

/**
 * Extrae información de archivos HTML
 * @param {string} filePath - Ruta del archivo
 * @returns {object} Información extraída
 */
function extractHtmlInfo(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const titleMatch = content.match(/<title>([^<]+)<\/title>/);
  const h1Match = content.match(/<h[1-2]>([^<]+)<\/h[1-2]>/);
  
  return {
    title: titleMatch ? titleMatch[1] : 'Sin título',
    heading: h1Match ? h1Match[1] : 'Sin encabezado'
  };
}

/**
 * Cuenta líneas de código en un archivo
 * @param {string} filePath - Ruta del archivo
 * @returns {number} Número de líneas
 */
function countLines(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  return content.split('\n').length;
}

/**
 * Genera el contenido del README
 * @returns {string} Contenido del README formateado
 */
function generateReadmeContent() {
  const projectName = path.basename(projectRoot);
  const tree = generateTree(projectRoot);

  // Información de archivos
  let htmlFiles = [];
  let cssFiles = [];
  let otherFiles = [];

  const files = fs.readdirSync(projectRoot).filter(file => {
    const ext = path.extname(file);
    return ['.html', '.css', '.js', '.txt', '.json'].includes(ext);
  });

  files.forEach(file => {
    const filePath = path.join(projectRoot, file);
    const stats = fs.statSync(filePath);
    const ext = path.extname(file);

    if (ext === '.html') {
      const info = extractHtmlInfo(filePath);
      htmlFiles.push({
        name: file,
        title: info.title,
        lines: countLines(filePath),
        size: (stats.size / 1024).toFixed(2)
      });
    } else if (ext === '.css') {
      cssFiles.push({
        name: file,
        lines: countLines(filePath),
        size: (stats.size / 1024).toFixed(2)
      });
    } else {
      otherFiles.push({
        name: file,
        lines: countLines(filePath),
        size: (stats.size / 1024).toFixed(2)
      });
    }
  });

  // Generar tabla de archivos HTML
  let htmlTable = '';
  if (htmlFiles.length > 0) {
    htmlTable = '\n| Archivo | Título | Líneas | Tamaño |\n';
    htmlTable += '|---------|--------|--------|--------|\n';
    htmlFiles.forEach(file => {
      htmlTable += `| ${file.name} | ${file.title} | ${file.lines} | ${file.size} KB |\n`;
    });
  }

  // Generar tabla de archivos CSS
  let cssTable = '';
  if (cssFiles.length > 0) {
    cssTable = '\n| Archivo | Líneas | Tamaño |\n';
    cssTable += '|---------|--------|--------|\n';
    cssFiles.forEach(file => {
      cssTable += `| ${file.name} | ${file.lines} | ${file.size} KB |\n`;
    });
  }

  // Generar tabla de otros archivos
  let otherTable = '';
  if (otherFiles.length > 0) {
    otherTable = '\n| Archivo | Líneas | Tamaño |\n';
    otherTable += '|---------|--------|--------|\n';
    otherFiles.forEach(file => {
      otherTable += `| ${file.name} | ${file.lines} | ${file.size} KB |\n`;
    });
  }

  const timestamp = new Date().toLocaleString('es-ES');

  return `# PixelHub - Comunidad y Servidor Minecraft

> Plataforma web para gestionar una comunidad gaming con servidor personalizado de Minecraft

## 📋 Descripción

PixelHub es una plataforma web desarrollada para gestionar y promover una comunidad gaming, con enfoque especial en un servidor personalizado de Minecraft. El sitio proporciona información sobre la comunidad, características del servidor y acceso a recursos relacionados.

## 🗂️ Estructura del Proyecto

\`\`\`
${projectName}/
${tree}
\`\`\`

**Generado automáticamente**: ${timestamp}

## 📄 Archivos HTML${htmlTable}

### Descripción de Páginas
${htmlFiles.map(file => `- **${file.name}** (${file.lines} líneas): ${file.title}`).join('\n')}

## 🎨 Estilos${cssTable}

Los estilos utilizan variables CSS y se adaptan a:
- Tema oscuro/claro
- Accesibilidad WCAG AA
- Diseño responsivo

## 📦 Otros Archivos${otherTable}

## 🚀 Características

- ✅ Diseño accesible (WCAG AA)
- ✅ Modo oscuro/claro
- ✅ Navegación intuitiva
- ✅ Responsivo (mobile-friendly)
- ✅ Soporte en español
- ✅ Estructura modular

## 🔧 Tecnologías

- HTML5
- CSS3
- JavaScript (Node.js para automatización)
- Accesibilidad web (ARIA, WCAG)

## 📱 Navegación Principal

1. **Inicio** - Página de inicio del proyecto
2. **Comunidad** - Información de la comunidad PixelHub
3. **Servidor de Minecraft** - Detalles del servidor con minijuegos

## 🎮 Características del Servidor Minecraft

- Survival custom
- Sistema de niveles avanzado
- Minijuegos: Skywars, Paintball
- Capture the Wool (en desarrollo)

## 💻 Ejecutar Generador de README

Para regenerar este archivo automáticamente:

\`\`\`bash
node generateREADME.js
\`\`\`

## 📊 Estadísticas del Proyecto

**Total de archivos analizados**: ${htmlFiles.length + cssFiles.length + otherFiles.length}
- Archivos HTML: ${htmlFiles.length}
- Archivos CSS: ${cssFiles.length}
- Otros archivos: ${otherFiles.length}

**Líneas totales de código**: ${(htmlFiles.reduce((sum, f) => sum + f.lines, 0) + cssFiles.reduce((sum, f) => sum + f.lines, 0) + otherFiles.reduce((sum, f) => sum + f.lines, 0))}

## 📝 Próximas Mejoras

- [ ] Captura the Wool - Minijuego en desarrollo
- [ ] Integración de más recursos multimedia
- [ ] Sistema de registro de usuarios
- [ ] Chat en tiempo real
- [ ] API REST para el servidor

## 🤝 Contribución

Para contribuir al proyecto, asegúrate de:
1. Mantener la accesibilidad WCAG AA
2. Usar estilos consistentes
3. Documentar cambios importantes

## 📞 Contacto

Para más información sobre PixelHub y su servidor de Minecraft, consulta el archivo \`ia_consultas.txt\`.

---

**Última actualización**: ${timestamp}

*Este README fue generado automáticamente por generateREADME.js*
`;
}

/**
 * Genera y guarda el archivo README.md
 */
function main() {
  try {
    const readmeContent = generateReadmeContent();
    const readmePath = path.join(projectRoot, 'README.md');
    
    fs.writeFileSync(readmePath, readmeContent, 'utf8');
    
    console.log('✅ README.md generado exitosamente');
    console.log(`📄 Ubicación: ${readmePath}`);
    console.log(`📊 Tamaño: ${(readmeContent.length / 1024).toFixed(2)} KB`);
    console.log(`📝 Líneas: ${readmeContent.split('\n').length}`);
  } catch (error) {
    console.error('❌ Error al generar README.md:', error.message);
    process.exit(1);
  }
}

// Ejecutar el generador
main();
