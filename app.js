/**
 * PixelHub - Sistema de Autenticación, Carrusel y Eventos
 * IMPORTANTE: Este código utiliza localStorage para demostración.
 * En producción, todo el hashing y almacenamiento DEBE hacerse en el servidor
 * con protocolos seguros como bcrypt, JWT, HTTPS, etc.
 */

// ============================================================================
// SEGURIDAD: Funciones de validación y protección contra XSS
// ============================================================================

/**
 * Escapa caracteres especiales HTML para prevenir inyección XSS
 * Convierte caracteres como <, >, &, ", ' a sus entidades HTML
 * 
 * @param {string} str - Texto a escapar
 * @returns {string} Texto escapado
 * 
 * SEGURIDAD: Usar siempre que se inserte contenido de usuario en el DOM
 */
function escapeHtml(str) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return str.replace(/[&<>"']/g, (m) => map[m]);
}

/**
 * Simula hashing de contraseña con SHA-256 (solo para demo)
 * NOTA: En producción DEBE usarse bcrypt o similar en el servidor.
 * NUNCA confíes en hashing en cliente para seguridad real.
 * 
 * @param {string} password - Contraseña a hashear
 * @returns {Promise<string>} Hash de la contraseña
 * 
 * SEGURIDAD: Esta es solo una demostración educativa.
 * Implementar siempre en servidor con algoritmos seguros.
 */
async function hashPassword(password) {
  const msgBuffer = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// VALIDACIONES
// ============================================================================

/**
 * Valida un email con regex robusta (RFC 5322 simplificada)
 * Acepta: user@domain.ext, user+tag@domain.co.uk, etc.
 * 
 * @param {string} email - Email a validar
 * @returns {boolean} true si es válido
 */
function validarEmail(email) {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email);
}

/**
 * Valida que los campos no estén vacíos y cumplan requisitos mínimos
 * 
 * @param {object} campos - Objeto con pares {fieldName: fieldValue}
 * @returns {object} {valido: boolean, errores: {fieldName: errorMsg}}
 */
function validarCampos(campos) {
  const errores = {};
  let valido = true;

  for (const [nombre, valor] of Object.entries(campos)) {
    if (!valor || valor.trim() === '') {
      errores[nombre] = 'Este campo es requerido.';
      valido = false;
    }
  }

  return { valido, errores };
}

/**
 * Valida contraseña: mínimo 8 caracteres
 * 
 * @param {string} password - Contraseña a validar
 * @returns {object} {valido: boolean, error: string|null}
 */
function validarPassword(password) {
  if (password.length < 8) {
    return {
      valido: false,
      error: 'La contraseña debe tener al menos 8 caracteres.'
    };
  }
  return { valido: true, error: null };
}

/**
 * Valida que dos contraseñas coincidan
 * 
 * @param {string} password - Primera contraseña
 * @param {string} confirmPassword - Confirmación de contraseña
 * @returns {object} {valido: boolean, error: string|null}
 */
function validarCoincidenciaPassword(password, confirmPassword) {
  if (password !== confirmPassword) {
    return {
      valido: false,
      error: 'Las contraseñas no coinciden.'
    };
  }
  return { valido: true, error: null };
}

// ============================================================================
// GESTIÓN DE USUARIOS (localStorage)
// ============================================================================

// Clave para almacenar usuarios en localStorage
const USUARIOS_KEY = 'pixelhub_users';
const SESSION_KEY = 'pixelhub_session';
const INSCRIPTIONS_KEY = 'pixelhub_inscriptions';
const CUSTOM_EVENTS_KEY = 'pixelhub_custom_events';
const OTHER_EVENTS_KEY = 'pixelhub_other_events';
const POSTS_KEY = 'pixelhub_posts';
const COMPLAINTS_KEY = 'pixelhub_complaints';
const ADMIN_MODE_KEY = 'pixelhub_admin_mode';

let customEvents = [];
let otherEvents = [];
let posts = [];
let complaints = [];
let adminMode = false;

/**
 * Carga los usuarios desde localStorage
 * Estructura: Array de usuarios con {id, nombre, email, passwordHash, createdAt}
 * 
 * SEGURIDAD: En producción, esta información DEBE estar en el servidor
 * protegida con HTTPS y autenticación segura.
 * 
 * @returns {array} Array de usuarios
 */
function loadUsers() {
  const stored = localStorage.getItem(USUARIOS_KEY);
  return stored ? JSON.parse(stored) : [];
}

/**
 * Guarda los usuarios en localStorage
 * 
 * @param {array} users - Array de usuarios a guardar
 */
function saveUsers(users) {
  localStorage.setItem(USUARIOS_KEY, JSON.stringify(users));
}

function loadInscriptions() {
  const stored = localStorage.getItem(INSCRIPTIONS_KEY);
  return stored ? JSON.parse(stored) : {};
}

function saveInscriptions(inscriptions) {
  localStorage.setItem(INSCRIPTIONS_KEY, JSON.stringify(inscriptions));
}

function loadCustomEvents() {
  const stored = localStorage.getItem(CUSTOM_EVENTS_KEY);
  return stored ? JSON.parse(stored) : [];
}

function saveCustomEvents(customEventsData) {
  localStorage.setItem(CUSTOM_EVENTS_KEY, JSON.stringify(customEventsData));
}

function loadOtherEvents() {
  const stored = localStorage.getItem(OTHER_EVENTS_KEY);
  return stored ? JSON.parse(stored) : [];
}

function saveOtherEvents(otherEventsData) {
  localStorage.setItem(OTHER_EVENTS_KEY, JSON.stringify(otherEventsData));
}

function loadPosts() {
  const stored = localStorage.getItem(POSTS_KEY);
  return stored ? JSON.parse(stored) : [];
}

function savePosts(postsData) {
  localStorage.setItem(POSTS_KEY, JSON.stringify(postsData));
}

function loadComplaints() {
  const stored = localStorage.getItem(COMPLAINTS_KEY);
  return stored ? JSON.parse(stored) : [];
}

function saveComplaints(complaintsData) {
  localStorage.setItem(COMPLAINTS_KEY, JSON.stringify(complaintsData));
}

function loadAdminMode() {
  const stored = localStorage.getItem(ADMIN_MODE_KEY);
  return stored === 'true';
}

function saveAdminMode(value) {
  localStorage.setItem(ADMIN_MODE_KEY, value.toString());
}

/**
 * Registra un nuevo usuario
 * Valida todos los campos, genera hash de contraseña, asigna ID único
 * 
 * @param {object} formData - {nombre, email, password, confirmPassword}
 * @returns {object} {exito: boolean, mensaje: string, usuario: object|null}
 */
async function registrarUsuario(formData) {
  // Validar campos no vacíos
  const validacion = validarCampos({
    nombre: formData.nombre,
    email: formData.email,
    password: formData.password,
    confirmPassword: formData.confirmPassword
  });

  if (!validacion.valido) {
    return {
      exito: false,
      mensaje: 'Por favor completa todos los campos.',
      errores: validacion.errores
    };
  }

  // Validar email
  if (!validarEmail(formData.email)) {
    return {
      exito: false,
      mensaje: 'Email inválido.',
      errores: { email: 'Ingresa un email válido.' }
    };
  }

  // Validar contraseña
  const validPassword = validarPassword(formData.password);
  if (!validPassword.valido) {
    return {
      exito: false,
      mensaje: validPassword.error,
      errores: { password: validPassword.error }
    };
  }

  // Validar coincidencia de contraseñas
  const validMatch = validarCoincidenciaPassword(
    formData.password,
    formData.confirmPassword
  );
  if (!validMatch.valido) {
    return {
      exito: false,
      mensaje: validMatch.error,
      errores: { confirmPassword: validMatch.error }
    };
  }

  // Normalizar email para comparación consistente
  const normalizedEmail = formData.email.toLowerCase().trim();

  // Verificar si el email ya existe
  const users = loadUsers();
  if (users.some(u => u.email === normalizedEmail)) {
    return {
      exito: false,
      mensaje: 'Este email ya está registrado.',
      errores: { email: 'Email ya existe.' }
    };
  }

  // Crear usuario con contraseña hasheada
  const role = normalizedEmail === 'benjacastro942@gmail.com' ? 'admin' : 'user';
  const passwordHash = await hashPassword(formData.password);
  const nuevoUsuario = {
    id: Date.now(), // ID simple basado en timestamp
    nombre: escapeHtml(formData.nombre),
    email: normalizedEmail,
    passwordHash: passwordHash,
    role,
    createdAt: new Date().toISOString()
  };

  // Guardar usuario
  users.push(nuevoUsuario);
  saveUsers(users);

  return {
    exito: true,
    mensaje: 'Registro exitoso. Puedes iniciar sesión.',
    usuario: nuevoUsuario
  };
}

/**
 * Autentica un usuario con email y contraseña
 * 
 * @param {object} formData - {email, password}
 * @returns {object} {exito: boolean, mensaje: string, usuario: object|null}
 */
async function loginUsuario(formData) {
  // Validar campos no vacíos
  const validacion = validarCampos({
    email: formData.email,
    password: formData.password
  });

  if (!validacion.valido) {
    return {
      exito: false,
      mensaje: 'Por favor completa todos los campos.',
      errores: validacion.errores
    };
  }

  // Validar email
  if (!validarEmail(formData.email)) {
    return {
      exito: false,
      mensaje: 'Email inválido.',
      errores: { email: 'Email no válido.' }
    };
  }

  // Buscar usuario
  const users = loadUsers();
  const usuario = users.find(u => u.email === formData.email.toLowerCase());

  if (!usuario) {
    return {
      exito: false,
      mensaje: 'Email o contraseña incorrectos.',
      errores: { email: 'Usuario no encontrado.' }
    };
  }

  // Verificar contraseña
  const passwordHash = await hashPassword(formData.password);
  if (passwordHash !== usuario.passwordHash) {
    return {
      exito: false,
      mensaje: 'Email o contraseña incorrectos.',
      errores: { password: 'Contraseña incorrecta.' }
    };
  }

  // Crear sesión
  const session = {
    userId: usuario.id,
    nombre: usuario.nombre,
    email: usuario.email,
    role: usuario.role || 'user',
    loginTime: new Date().toISOString()
  };

  localStorage.setItem(SESSION_KEY, JSON.stringify(session));

  return {
    exito: true,
    mensaje: 'Sesión iniciada correctamente.',
    usuario: session
  };
}

/**
 * Cierra la sesión del usuario
 */
function logout() {
  localStorage.removeItem(SESSION_KEY);
}

/**
 * Obtiene el usuario de la sesión activa
 * 
 * @returns {object|null} Usuario logueado o null
 */
function getSessionUser() {
  const stored = localStorage.getItem(SESSION_KEY);
  return stored ? JSON.parse(stored) : null;
}

// ============================================================================
// GESTIÓN DE MODALES
// ============================================================================

/**
 * Abre un modal con overlay
 * Implementa cierre con ESC y click fuera
 * Focus trap básico (enfocar primer input)
 * 
 * @param {string} modalId - ID del modal
 */
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  const overlay = document.getElementById('modalOverlay');

  modal.style.display = 'block';
  overlay.style.display = 'block';

  // Enfocar primer input
  const firstInput = modal.querySelector('input');
  if (firstInput) {
    firstInput.focus();
  }

  // Cerrar con ESC
  const handleEscape = (e) => {
    if (e.key === 'Escape') {
      closeModal(modalId);
      document.removeEventListener('keydown', handleEscape);
    }
  };
  document.addEventListener('keydown', handleEscape);

  // Cerrar con click en overlay
  overlay.onclick = () => {
    closeModal(modalId);
  };
}

/**
 * Cierra un modal con overlay
 * 
 * @param {string} modalId - ID del modal
 */
function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  const overlay = document.getElementById('modalOverlay');
  const isAnyModalOpen =
    document.getElementById('loginModal').style.display === 'block' ||
    document.getElementById('registerModal').style.display === 'block';

  modal.style.display = 'none';

  if (!isAnyModalOpen) {
    overlay.style.display = 'none';
  }
}

/**
 * Muestra un mensaje de error en un campo
 * 
 * @param {string} fieldId - ID del campo input
 * @param {string} errorId - ID del elemento de error
 * @param {string} mensaje - Mensaje de error
 */
function mostrarError(fieldId, errorId, mensaje) {
  const errorElement = document.getElementById(errorId);
  if (errorElement) {
    errorElement.textContent = mensaje;
    errorElement.style.display = 'block';
  }
  const field = document.getElementById(fieldId);
  if (field) {
    field.style.borderColor = '#e74c3c';
  }
}

/**
 * Limpia los errores de un campo
 * 
 * @param {string} fieldId - ID del campo input
 * @param {string} errorId - ID del elemento de error
 */
function limpiarError(fieldId, errorId) {
  const errorElement = document.getElementById(errorId);
  if (errorElement) {
    errorElement.textContent = '';
    errorElement.style.display = 'none';
  }
  const field = document.getElementById(fieldId);
  if (field) {
    field.style.borderColor = '';
  }
}

/**
 * Limpia los errores de todos los campos de un formulario
 * 
 * @param {array} errorIds - Array de IDs de elementos de error
 */
function limpiarTodosLosErrores(errorIds) {
  errorIds.forEach(errorId => {
    const element = document.getElementById(errorId);
    if (element) {
      element.textContent = '';
      element.style.display = 'none';
    }
  });
}

// ============================================================================
// CARRUSEL
// ============================================================================

// Array de imágenes del carrusel
const carouselImages = [
  'imagenes/pixelhub.png',
  'imagenes/pixelhubNoche.jpeg',
  'imagenes/logo.png'
];

let currentImageIndex = 0;
let carouselInterval = null;
const carouselDelay = 4000;

/**
 * Inicializa el carrusel: crea indicadores y configura botones
 */
function inicializarCarrusel() {
  const indicators = document.getElementById('carouselIndicators');
  indicators.innerHTML = '';

  // Crear indicadores
  carouselImages.forEach((_, index) => {
    const indicator = document.createElement('button');
    indicator.className = 'carousel-indicator';
    if (index === 0) indicator.classList.add('active');
    indicator.setAttribute('aria-label', `Ir a imagen ${index + 1}`);
    indicator.addEventListener('click', () => {
      currentImageIndex = index;
      actualizarCarrusel();
      resetAutoplay();
    });
    indicators.appendChild(indicator);
  });

  // Botones Anterior y Siguiente
  document.getElementById('prevBtn').addEventListener('click', () => {
    cambiarImagen(-1);
    resetAutoplay();
  });

  document.getElementById('nextBtn').addEventListener('click', () => {
    cambiarImagen(1);
    resetAutoplay();
  });

  const carouselWrapper = document.querySelector('.carousel-wrapper');
  carouselWrapper.addEventListener('mouseenter', pausarAutoplay);
  carouselWrapper.addEventListener('mouseleave', iniciarAutoplay);

  // Inicializar primera imagen
  actualizarCarrusel();
  iniciarAutoplay();
}

function iniciarAutoplay() {
  pausarAutoplay();
  carouselInterval = setInterval(() => cambiarImagen(1, false), carouselDelay);
}

function pausarAutoplay() {
  if (carouselInterval) {
    clearInterval(carouselInterval);
    carouselInterval = null;
  }
}

function resetAutoplay() {
  pausarAutoplay();
  iniciarAutoplay();
}

/**
 * Cambia la imagen del carrusel (anterior o siguiente)
 * 
 * @param {number} delta - -1 para anterior, +1 para siguiente
 * @param {boolean} resetTimer - si debe reiniciar el autoplay tras el cambio
 */
function cambiarImagen(delta, resetTimer = true) {
  currentImageIndex += delta;

  // Circular
  if (currentImageIndex < 0) {
    currentImageIndex = carouselImages.length - 1;
  } else if (currentImageIndex >= carouselImages.length) {
    currentImageIndex = 0;
  }

  actualizarCarrusel();
  if (resetTimer) {
    resetAutoplay();
  }
}

/**
 * Actualiza el DOM del carrusel con la imagen actual
 */
function actualizarCarrusel() {
  const img = document.getElementById('carouselImg');
  img.style.opacity = '0';
  img.onload = () => {
    img.style.opacity = '1';
    img.onload = null;
  };
  img.src = carouselImages[currentImageIndex];

  // Actualizar indicadores
  document.querySelectorAll('.carousel-indicator').forEach((indicator, index) => {
    if (index === currentImageIndex) {
      indicator.classList.add('active');
    } else {
      indicator.classList.remove('active');
    }
  });
}

// ============================================================================
// EVENTOS PROTEGIDOS
// ============================================================================

/**
 * Array de eventos con estructura:
 * {titulo, horario, descripcion, requiresAuth: true}
 */
const DEFAULT_EVENTS = [
  {
    id: 1,
    titulo: 'Furia De Bedwars',
    horario: 'Viernes 20:00 - 22:00 (Hora Estándar)',
    descripcion: 'Aquí se realizará la competencia más épica. ¡Más camas destruidas ganas el torneo! Compite contra otros jugadores y demuestra quién es el mejor defensor.',
    requiresAuth: true,
    icono: '⚔️'
  },
  {
    id: 2,
    titulo: 'Mejor Casa',
    horario: 'Sábado 15:00 - 17:00 (Hora Estándar)',
    descripcion: 'Arma tu mejor casa en survival y compite por el título de arquitecto más creativo. Los jueces evaluarán diseño, creatividad y detalles.',
    requiresAuth: true,
    icono: '🏠'
  },
  {
    id: 3,
    titulo: 'Torneo Skywars',
    horario: 'Domingo 18:00 - 20:30 (Hora Estándar)',
    descripcion: 'Compite en rondas de 24 mapas y obtén el mayor puntaje. Cada mapa presenta nuevos desafíos. ¡Solo los mejores llegarán a la final!',
    requiresAuth: true,
    icono: '☁️'
  }
];

let events = [...DEFAULT_EVENTS];

// Array para almacenar inscripciones de usuario (simulado)
let userInscriptions = {};

/**
 * Renderiza los eventos
 * - Si hay sesión: muestra título, horario y descripción completa
 * - Si NO hay sesión: muestra CTA con botón para login
 */
function renderRegistrationSummary() {
  const users = loadUsers();
  const inscriptions = loadInscriptions();
  const usersList = document.getElementById('registeredUsersList');
  const emailsList = document.getElementById('registeredEmailsList');
  const eventInscriptionsList = document.getElementById('eventInscriptionsList');

  if (!usersList || !emailsList || !eventInscriptionsList) {
    return;
  }

  usersList.innerHTML = '';
  emailsList.innerHTML = '';
  eventInscriptionsList.innerHTML = '';

  if (users.length === 0) {
    usersList.innerHTML = '<li>No hay usuarios registrados todavía.</li>';
    emailsList.innerHTML = '<li>No hay correos registrados todavía.</li>';
  } else {
    users.forEach(user => {
      const item = document.createElement('li');
      item.textContent = `${user.nombre} — ${user.email}`;
      usersList.appendChild(item);
    });

    const latestUsers = users.slice(-5).reverse();
    latestUsers.forEach(user => {
      const item = document.createElement('li');
      item.textContent = user.email;
      emailsList.appendChild(item);
    });
  }

  events.forEach(event => {
    const eventGroup = document.createElement('div');
    eventGroup.className = 'summary-event-group';

    const title = document.createElement('p');
    title.className = 'summary-event-title';
    title.textContent = event.titulo;
    eventGroup.appendChild(title);

    const registrants = Object.entries(inscriptions)
      .filter(([_, eventIds]) => Array.isArray(eventIds) && eventIds.includes(event.id))
      .map(([userId]) => {
        const foundUser = users.find(user => String(user.id) === String(userId));
        return foundUser ? `${foundUser.nombre} — ${foundUser.email}` : `Usuario eliminado (${userId})`;
      });

    if (registrants.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'summary-empty';
      empty.textContent = 'Nadie inscrito aún.';
      eventGroup.appendChild(empty);
    } else {
      const list = document.createElement('ul');
      list.className = 'summary-list';
      registrants.forEach(text => {
        const item = document.createElement('li');
        item.textContent = text;
        list.appendChild(item);
      });
      eventGroup.appendChild(list);
    }

    eventInscriptionsList.appendChild(eventGroup);
  });
}

function renderEvents() {
  const container = document.getElementById('events-container');
  container.innerHTML = '';

  const sessionUser = getSessionUser();

  events.forEach(event => {
    const eventCard = document.createElement('div');
    eventCard.className = 'event-card';
    eventCard.setAttribute('role', 'article');
    eventCard.setAttribute('aria-label', `Evento: ${event.titulo}`);

    if (sessionUser) {
      // Usuario logueado: mostrar detalles
      const isInscribed = userInscriptions[sessionUser.userId]?.includes(event.id);
      
      eventCard.innerHTML = `
        <div class="event-content">
          <h3>${escapeHtml(event.titulo)} ${event.icono}</h3>
          <p class="event-horario"><strong>Horario:</strong> ${escapeHtml(event.horario)}</p>
          <p class="event-descripcion">${escapeHtml(event.descripcion)}</p>
          <button 
            class="button ${isInscribed ? 'secondary' : 'primary'}" 
            data-event-id="${event.id}"
            onclick="inscribirseAlEvento(${event.id})"
          >
            ${isInscribed ? '✓ Inscrito' : 'Inscribirse'}
          </button>
        </div>
      `;
    } else {
      // Usuario NO logueado: mostrar CTA
      eventCard.innerHTML = `
        <div class="event-content event-locked">
          <h3>${escapeHtml(event.titulo)} ${event.icono}</h3>
          <p class="event-horario"><strong>Horario:</strong> ${escapeHtml(event.horario)}</p>
          <p class="event-cta">
            🔒 Debes iniciar sesión para ver los detalles del evento.
          </p>
          <button 
            class="button primary" 
            onclick="openModal('loginModal')"
          >
            Iniciar Sesión
          </button>
        </div>
      `;
    }

    container.appendChild(eventCard);
  });
}

function renderOtherEventsSection() {
  const container = document.getElementById('other-events-container');
  if (!container) return;

  container.innerHTML = '';

  if (otherEvents.length === 0) {
    container.innerHTML = '<p class="event-cta">No hay otros eventos todavía. Los administradores pueden crear esta sección.</p>';
    return;
  }

  otherEvents.forEach(otherEvent => {
    const eventCard = document.createElement('div');
    eventCard.className = 'event-card';
    eventCard.setAttribute('role', 'article');
    eventCard.innerHTML = `
      <div class="event-content">
        <h3>${escapeHtml(otherEvent.titulo)}</h3>
        <p class="event-descripcion">${escapeHtml(otherEvent.descripcion)}</p>
      </div>
    `;
    container.appendChild(eventCard);
  });
}

function renderPosts() {
  const container = document.getElementById('postsContainer');
  if (!container) return;

  container.innerHTML = '';

  if (posts.length === 0) {
    container.innerHTML = '<p class="event-cta">Aún no hay publicaciones. Inicia sesión para compartir tu casa de Minecraft.</p>';
    updateCarouselPosts();
    return;
  }

  const sessionUser = getSessionUser();

  posts.forEach(post => {
    const postCard = document.createElement('article');
    postCard.className = 'post-card';
    postCard.setAttribute('role', 'article');
    
    const canDelete = sessionUser && (sessionUser.userId === post.userId || (adminMode && sessionUser.role === 'admin'));
    const likes = post.likes || 0;
    const comments = post.comments || [];
    const isLiked = post.likedBy && post.likedBy.includes(sessionUser?.userId);
    
    postCard.innerHTML = `
      <div class="post-header">
        <strong>${escapeHtml(post.author)}</strong>
        <span>${new Date(post.createdAt).toLocaleString()}</span>
      </div>
      <p class="post-message">${escapeHtml(post.mensaje).replace(/\n/g, '<br/>')}</p>
      ${post.image ? `<img src="${post.image}" alt="Imagen de publicación de ${escapeHtml(post.author)}" class="post-image" />` : ''}
      <div class="post-actions">
        <button class="post-action-btn ${isLiked ? 'liked' : ''}" type="button" onclick="handleLikePost(${post.id})">
          ❤️ Me gusta (${likes})
        </button>
        <button class="post-action-btn" type="button" onclick="openCommentsModal(${post.id})">
          💬 Comentarios (${comments.length})
        </button>
        ${canDelete ? `<button class="post-action-btn delete" type="button" onclick="handleDeletePost(${post.id})">🗑️ Eliminar</button>` : ''}
      </div>
    `;
    container.appendChild(postCard);
  });
  
  updateCarouselPosts();
}

function handleLikePost(postId) {
  const post = posts.find(p => p.id === postId);
  if (!post) return;

  const sessionUser = getSessionUser();
  if (!sessionUser) {
    openModal('loginModal');
    return;
  }

  if (!post.likedBy) {
    post.likedBy = [];
  }
  if (!post.likes) {
    post.likes = 0;
  }

  const likeIndex = post.likedBy.indexOf(sessionUser.userId);
  if (likeIndex > -1) {
    post.likedBy.splice(likeIndex, 1);
    post.likes = Math.max(0, post.likes - 1);
  } else {
    post.likedBy.push(sessionUser.userId);
    post.likes++;
  }

  savePosts(posts);
  renderPosts();
}

function openCommentsModal(postId) {
  const post = posts.find(p => p.id === postId);
  if (!post) return;

  if (!post.comments) {
    post.comments = [];
  }

  let commentsHTML = '<div class="comments-list">';
  if (post.comments.length === 0) {
    commentsHTML += '<p style="text-align: center; color: var(--text);">No hay comentarios aún. ¡Sé el primero!</p>';
  } else {
    post.comments.forEach(comment => {
      commentsHTML += `
        <div class="comment-item">
          <div class="comment-author">${escapeHtml(comment.author)}</div>
          <p class="comment-text">${escapeHtml(comment.text)}</p>
        </div>
      `;
    });
  }
  commentsHTML += '</div>';

  const sessionUser = getSessionUser();
  let formHTML = '';
  if (sessionUser) {
    formHTML = `
      <form onsubmit="handleAddComment(event, ${postId})" style="margin-top: 1rem; border-top: 1px solid rgba(0, 90, 156, 0.2); padding-top: 1rem;">
        <textarea id="commentText" placeholder="Escribe un comentario..." style="width: 100%; padding: 0.75rem; border: 1px solid var(--primary); border-radius: 8px; font-family: inherit; resize: vertical; min-height: 80px; background: var(--bg); color: var(--text);" required></textarea>
        <button type="submit" class="button primary" style="width: 100%; margin-top: 0.75rem;">Comentar</button>
      </form>
    `;
  } else {
    formHTML = '<p style="text-align: center; color: var(--text); margin-top: 1rem;"><a href="#" onclick="openModal(\'loginModal\'); return false;" style="color: var(--primary);">Inicia sesión para comentar</a></p>';
  }

  const modal = document.createElement('div');
  modal.className = 'comments-modal active';
  modal.innerHTML = `
    <div class="comments-modal-header">
      <h3>Comentarios de ${escapeHtml(post.author)}</h3>
      <button type="button" class="comments-close-btn" onclick="this.closest('.comments-modal').remove(); document.getElementById('commentOverlay').remove();">×</button>
    </div>
    ${commentsHTML}
    ${formHTML}
  `;

  const overlay = document.createElement('div');
  overlay.id = 'commentOverlay';
  overlay.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); z-index: 1000;';
  overlay.onclick = function() {
    modal.remove();
    this.remove();
  };

  document.body.appendChild(overlay);
  document.body.appendChild(modal);

  window.currentCommentPostId = postId;
}

function handleAddComment(e, postId) {
  e.preventDefault();

  const sessionUser = getSessionUser();
  if (!sessionUser) {
    openModal('loginModal');
    return;
  }

  const commentText = document.getElementById('commentText').value.trim();
  if (!commentText) {
    return;
  }

  const post = posts.find(p => p.id === postId);
  if (!post) return;

  if (!post.comments) {
    post.comments = [];
  }

  post.comments.push({
    author: sessionUser.nombre,
    text: commentText,
    createdAt: new Date().toISOString()
  });

  savePosts(posts);
  
  // Cerrar modal y reabrirlo actualizado
  document.querySelector('.comments-modal').remove();
  document.getElementById('commentOverlay').remove();
  openCommentsModal(postId);
  
  mostrarToast('Comentario agregado.');
}
}

function setAdminMode(value) {
  adminMode = value;
  saveAdminMode(value);
  const adminOnlySection = document.getElementById('admin-only-section');
  const toggleBtn = document.getElementById('toggleAdminModeBtn');
  if (adminOnlySection) {
    adminOnlySection.style.display = value ? 'block' : 'none';
  }
  if (toggleBtn) {
    toggleBtn.textContent = value ? 'Salir Modo Admin' : 'Modo Admin';
    toggleBtn.setAttribute('aria-label', value ? 'Desactivar modo admin' : 'Activar modo admin');
  }
  renderPosts();
  renderAdminPanel();
}

function toggleAdminMode() {
  const sessionUser = getSessionUser();
  if (!sessionUser || sessionUser.role !== 'admin') return;
  setAdminMode(!adminMode);
}

function renderAdminPanel() {
  const sessionUser = getSessionUser();
  const adminOnlySection = document.getElementById('admin-only-section');
  if (!adminOnlySection) return;

  if (!adminMode || !sessionUser || sessionUser.role !== 'admin') {
    adminOnlySection.style.display = 'none';
    return;
  }

  adminOnlySection.style.display = 'block';

  const users = loadUsers();
  const emailsList = document.getElementById('registeredEmailsList');
  const complaintsList = document.getElementById('complaintsList');
  const adminEmailsList = document.getElementById('adminEmailsList');

  if (emailsList) {
    emailsList.innerHTML = '';
    users.forEach(user => {
      const item = document.createElement('li');
      item.textContent = `${user.email}`;
      emailsList.appendChild(item);
    });
  }

  if (complaintsList) {
    complaintsList.innerHTML = '';
    if (complaints.length === 0) {
      complaintsList.innerHTML = '<li>No hay quejas registradas.</li>';
    } else {
      complaints.slice().reverse().forEach(complaint => {
        const item = document.createElement('li');
        item.innerHTML = `<strong>${escapeHtml(complaint.nombre || 'Anonimo')}</strong>: ${escapeHtml(complaint.mensaje)} <span class="complaint-meta">(${new Date(complaint.createdAt).toLocaleString()})</span>`;
        complaintsList.appendChild(item);
      });
    }
  }

  if (adminEmailsList) {
    adminEmailsList.innerHTML = '';
    users.filter(user => user.role === 'admin').forEach(admin => {
      const item = document.createElement('li');
      item.textContent = admin.email;
      adminEmailsList.appendChild(item);
    });
  }
}

function handleAddAdminByEmail(e) {
  e.preventDefault();
  const sessionUser = getSessionUser();
  if (!sessionUser || sessionUser.email !== 'benjacastro942@gmail.com') {
    mostrarToast('Solo benjacastro942@gmail.com puede agregar admins.');
    return;
  }
  const emailInput = document.getElementById('addAdminEmail');
  const email = emailInput.value.trim().toLowerCase();
  if (!validarEmail(email)) {
    mostrarError('addAdminEmail', 'addAdminEmailError', 'Email inválido');
    return;
  }
  const users = loadUsers();
  const userToUpdate = users.find(u => u.email === email);
  if (!userToUpdate) {
    mostrarError('addAdminEmail', 'addAdminEmailError', 'No existe un usuario registrado con ese correo.');
    return;
  }
  userToUpdate.role = 'admin';
  saveUsers(users);
  emailInput.value = '';
  renderAdminPanel();
  actualizarDOMAuthState();
  mostrarToast(`${email} ahora es administrador.`);
}

function createPost(sessionUser, message, imageDataUrl) {
  const newPost = {
    id: Date.now(),
    author: sessionUser.nombre,
    userId: sessionUser.userId,
    mensaje: message,
    image: imageDataUrl,
    createdAt: new Date().toISOString(),
    likes: 0,
    likedBy: [],
    comments: []
  };

  posts.unshift(newPost);
  savePosts(posts);
  renderPosts();
  document.getElementById('postForm').reset();
  mostrarToast('Publicación creada.');
}

function handleDeletePost(postId) {
  posts = posts.filter(post => post.id !== postId);
  savePosts(posts);
  renderPosts();
  mostrarToast('Publicación eliminada.');
}

function handlePostSubmit(e) {
  e.preventDefault();

  const sessionUser = getSessionUser();
  if (!sessionUser) {
    openModal('loginModal');
    return;
  }

  const message = document.getElementById('postMessage').value.trim();
  if (!message) {
    mostrarError('postMessage', 'postMessageError', 'Escribe algo para publicar.');
    return;
  }

  const imageInput = document.getElementById('postImage');
  const file = imageInput.files[0];
  if (file) {
    const reader = new FileReader();
    reader.onload = (event) => {
      createPost(sessionUser, message, event.target.result);
    };
    reader.readAsDataURL(file);
  } else {
    createPost(sessionUser, message, null);
  }
}

function handleAdminAddEvent(e) {
  e.preventDefault();

  const sessionUser = getSessionUser();
  if (!sessionUser || sessionUser.role !== 'admin') {
    mostrarToast('Solo administradores pueden agregar eventos.');
    return;
  }

  const title = document.getElementById('adminEventTitle').value.trim();
  const horario = document.getElementById('adminEventHorario').value.trim();
  const descripcion = document.getElementById('adminEventDescription').value.trim();
  const icono = document.getElementById('adminEventIcon').value.trim() || '✨';

  if (!title || !horario || !descripcion) {
    mostrarToast('Completa todos los campos para agregar un evento.');
    return;
  }

  const newEvent = {
    id: Date.now(),
    titulo: title,
    horario,
    descripcion,
    requiresAuth: true,
    icono
  };

  customEvents.unshift(newEvent);
  saveCustomEvents(customEvents);
  events = [...DEFAULT_EVENTS, ...customEvents];
  renderEvents();
  renderRegistrationSummary();
  document.getElementById('adminAddEventForm').reset();
  mostrarToast('Evento agregado correctamente.');
}

function handleAdminAddOtherEvent(e) {
  e.preventDefault();

  const sessionUser = getSessionUser();
  if (!sessionUser || sessionUser.role !== 'admin') {
    mostrarToast('Solo administradores pueden crear otros eventos.');
    return;
  }

  const title = document.getElementById('adminOtherEventTitle').value.trim();
  const descripcion = document.getElementById('adminOtherEventDescription').value.trim();

  if (!title || !descripcion) {
    mostrarToast('Completa todos los campos para crear el otro evento.');
    return;
  }

  const otherEvent = {
    id: Date.now(),
    titulo: title,
    descripcion
  };

  otherEvents.unshift(otherEvent);
  saveOtherEvents(otherEvents);
  renderOtherEventsSection();
  document.getElementById('adminAddOtherEventForm').reset();
  mostrarToast('Otro evento agregado a la sección correctamente.');
}

function initializeEvents() {
  customEvents = loadCustomEvents();
  otherEvents = loadOtherEvents();
  posts = loadPosts();
  complaints = loadComplaints();
  adminMode = loadAdminMode();
  events = [...DEFAULT_EVENTS, ...customEvents];
}

/**
 * Simula la inscripción a un evento
 * Muestra un mensaje de éxito
 * 
 * @param {number} eventId - ID del evento
 */
function inscribirseAlEvento(eventId) {
  const sessionUser = getSessionUser();
  if (!sessionUser) {
    openModal('loginModal');
    return;
  }

  // Inicializar si no existe
  if (!userInscriptions[sessionUser.userId]) {
    userInscriptions[sessionUser.userId] = [];
  }

  // Toggle inscripción
  const inscriptions = userInscriptions[sessionUser.userId];
  const index = inscriptions.indexOf(eventId);

  if (index === -1) {
    inscriptions.push(eventId);
    mostrarToast(`¡Inscripción confirmada! Te esperamos en el evento. 🎉`);
  } else {
    inscriptions.splice(index, 1);
    mostrarToast('Inscripción cancelada.');
  }

  saveInscriptions(userInscriptions);

  // Re-renderizar eventos y resumen de inscripciones
  renderEvents();
  renderRegistrationSummary();
}

/**
 * Muestra un toast (notificación temporal) en la pantalla
 * 
 * @param {string} mensaje - Mensaje a mostrar
 */
function mostrarToast(mensaje) {
  // Crear elemento de toast
  const toast = document.createElement('div');
  toast.className = 'toast-notification';
  toast.setAttribute('role', 'status');
  toast.setAttribute('aria-live', 'polite');
  toast.textContent = mensaje;
  
  document.body.appendChild(toast);

  // Animar entrada
  setTimeout(() => toast.classList.add('show'), 10);

  // Remover después de 3 segundos
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ============================================================================
// AUTENTICACIÓN: Actualización dinámica del DOM
// ============================================================================

/**
 * Actualiza el estado de autenticación en el header
 * Muestra/oculta botones según si hay sesión activa
 */
function actualizarDOMAuthState() {
  const sessionUser = getSessionUser();
  const loginBtn = document.getElementById('loginBtn');
  const registerBtn = document.getElementById('registerBtn');
  const userGreeting = document.getElementById('userGreeting');
  const userNameDisplay = document.getElementById('userNameDisplay');
  const adminToggleBtn = document.getElementById('toggleAdminModeBtn');

  if (sessionUser) {
    // Usuario logueado
    loginBtn.style.display = 'none';
    registerBtn.style.display = 'none';
    userGreeting.style.display = 'flex';
    userNameDisplay.textContent = `Hola, ${escapeHtml(sessionUser.nombre)}`;
    if (adminToggleBtn) {
      adminToggleBtn.style.display = sessionUser.role === 'admin' ? 'block' : 'none';
    }
  } else {
    // Usuario NO logueado
    loginBtn.style.display = 'block';
    registerBtn.style.display = 'block';
    userGreeting.style.display = 'none';
    if (adminToggleBtn) {
      adminToggleBtn.style.display = 'none';
    }
  }

  // Mantener el modo admin activo si corresponde
  if (sessionUser && sessionUser.role === 'admin') {
    setAdminMode(adminMode);
  } else {
    setAdminMode(false);
  }

  // Re-renderizar eventos, otros eventos y publicaciones
  userInscriptions = loadInscriptions();
  renderEvents();
  renderRegistrationSummary();
  renderOtherEventsSection();
  renderPosts();
}

// ============================================================================
// GESTIÓN DE FORMULARIOS
// ============================================================================

/**
 * Maneja el envío del formulario de login
 */
async function handleLoginSubmit(e) {
  e.preventDefault();

  // Limpiar errores previos
  limpiarTodosLosErrores([
    'loginEmailError',
    'loginPasswordError'
  ]);

  const email = document.getElementById('loginEmail').value;
  const password = document.getElementById('loginPassword').value;

  // Loginear
  const result = await loginUsuario({ email, password });

  if (result.exito) {
    // Éxito
    mostrarToast('¡Bienvenido de vuelta! 🎮');
    actualizarDOMAuthState();
    closeModal('loginModal');
    document.getElementById('loginForm').reset();
  } else {
    // Error
    if (result.errores) {
      Object.entries(result.errores).forEach(([field, error]) => {
        if (field === 'email') {
          mostrarError('loginEmail', 'loginEmailError', error);
        } else if (field === 'password') {
          mostrarError('loginPassword', 'loginPasswordError', error);
        }
      });
    }
    document.getElementById('loginError').textContent = result.mensaje;
  }
}

/**
 * Maneja el envío del formulario de registro
 */
async function handleRegisterSubmit(e) {
  e.preventDefault();

  // Limpiar errores previos
  limpiarTodosLosErrores([
    'registerNameError',
    'registerEmailError',
    'registerPasswordError',
    'registerConfirmPasswordError'
  ]);

  const nombre = document.getElementById('registerName').value;
  const email = document.getElementById('registerEmail').value;
  const password = document.getElementById('registerPassword').value;
  const confirmPassword = document.getElementById('registerConfirmPassword').value;

  // Registrar
  const result = await registrarUsuario({
    nombre,
    email,
    password,
    confirmPassword
  });

  if (result.exito) {
    // Éxito
    mostrarToast('¡Registro exitoso! Ahora inicia sesión. 🚀');
    closeModal('registerModal');
    document.getElementById('registerForm').reset();
    renderRegistrationSummary();
    
    // Abrir modal de login automáticamente
    setTimeout(() => {
      openModal('loginModal');
    }, 500);
  } else {
    // Error
    if (result.errores) {
      Object.entries(result.errores).forEach(([field, error]) => {
        const fieldId = `register${field.charAt(0).toUpperCase() + field.slice(1)}`;
        const errorId = `${fieldId}Error`;
        mostrarError(fieldId, errorId, error);
      });
    }
    document.getElementById('registerError').textContent = result.mensaje;
  }
}

/**
 * Maneja el envío del formulario de contacto
 */
function handleContactSubmit(e) {
  e.preventDefault();

  // Limpiar errores previos
  limpiarTodosLosErrores([
    'contactNameError',
    'contactEmailError',
    'contactMessageError'
  ]);

  const nombre = document.getElementById('contactName').value;
  const email = document.getElementById('contactEmail').value;
  const mensaje = document.getElementById('contactMessage').value;

  // Validar campos
  const validacion = validarCampos({ nombre, email, mensaje });
  if (!validacion.valido) {
    Object.entries(validacion.errores).forEach(([field, error]) => {
      const fieldId = `contact${field.charAt(0).toUpperCase() + field.slice(1)}`;
      const errorId = `${fieldId}Error`;
      mostrarError(fieldId, errorId, error);
    });
    return;
  }

  // Validar email
  if (!validarEmail(email)) {
    mostrarError('contactEmail', 'contactEmailError', 'Email inválido');
    return;
  }

  // Guardar queja para administradores
  const sessionUser = getSessionUser();
  const complaint = {
    id: Date.now(),
    nombre: sessionUser ? sessionUser.nombre : escapeHtml(nombre),
    email: sessionUser ? sessionUser.email : email.toLowerCase().trim(),
    mensaje: escapeHtml(mensaje),
    createdAt: new Date().toISOString()
  };
  complaints.unshift(complaint);
  saveComplaints(complaints);

  // Simular envío (en producción, hacer POST a servidor)
  mostrarToast('¡Mensaje enviado! Nos pondremos en contacto pronto. 📧');
  document.getElementById('contactForm').reset();
  document.getElementById('contactSuccess').style.display = 'block';
  document.getElementById('contactSuccess').textContent =
    'Gracias por tu mensaje. Responderemos pronto.';

  renderAdminPanel();

  // Ocultar mensaje después de 4 segundos
  setTimeout(() => {
    document.getElementById('contactSuccess').style.display = 'none';
  }, 4000);
}

// ============================================================================
// CARRUSEL DE POSTS
// ============================================================================

let carouselPostIndex = 0;
let carouselPostInterval = null;

function updateCarouselPosts() {
  const carouselImage = document.getElementById('carouselPostImage');
  if (!carouselImage) return;

  const postsWithImages = posts.filter(post => post.image);

  if (postsWithImages.length === 0) {
    carouselImage.src = '';
    carouselImage.alt = 'No hay imágenes en los posts';
    carouselPostIndex = 0;
    clearInterval(carouselPostInterval);
    return;
  }

  // Mostrar primera imagen
  carouselImage.src = postsWithImages[carouselPostIndex].image;
  carouselImage.alt = `Imagen de ${escapeHtml(postsWithImages[carouselPostIndex].author)}`;

  // Limpiar intervalo anterior
  clearInterval(carouselPostInterval);

  // Cambiar imagen cada 2 segundos
  carouselPostInterval = setInterval(() => {
    carouselPostIndex = (carouselPostIndex + 1) % postsWithImages.length;
    carouselImage.src = postsWithImages[carouselPostIndex].image;
    carouselImage.alt = `Imagen de ${escapeHtml(postsWithImages[carouselPostIndex].author)}`;
  }, 2000);
}

// ============================================================================
// INICIALIZACIÓN (DOMContentLoaded)
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
  initializeEvents();
  actualizarDOMAuthState();

  // ---- EVENTOS DEL HEADER ----
  document.getElementById('loginBtn').addEventListener('click', () => {
    openModal('loginModal');
  });

  document.getElementById('registerBtn').addEventListener('click', () => {
    openModal('registerModal');
  });

  document.getElementById('logoutBtn').addEventListener('click', () => {
    logout();
    actualizarDOMAuthState();
    mostrarToast('Sesión cerrada. ¡Hasta pronto! 👋');
  });

  const adminToggleBtn = document.getElementById('toggleAdminModeBtn');
  if (adminToggleBtn) {
    adminToggleBtn.addEventListener('click', () => {
      toggleAdminMode();
    });
  }

  const openAdminModalBtn = document.getElementById('openAdminModalBtn');
  if (openAdminModalBtn) {
    openAdminModalBtn.addEventListener('click', () => {
      openModal('adminModal');
    });
  }

  const addAdminForm = document.getElementById('addAdminForm');
  if (addAdminForm) {
    addAdminForm.addEventListener('submit', handleAddAdminByEmail);
  }

  // ---- CERRAR MODALES ----
  document.getElementById('closeLoginBtn').addEventListener('click', () => {
    closeModal('loginModal');
  });

  document.getElementById('closeRegisterBtn').addEventListener('click', () => {
    closeModal('registerModal');
  });

  const closeAdminBtn = document.getElementById('closeAdminBtn');
  if (closeAdminBtn) {
    closeAdminBtn.addEventListener('click', () => {
      closeModal('adminModal');
    });
  }

  // ---- CAMBIAR ENTRE MODALES ----
  document.getElementById('switchToRegisterBtn').addEventListener('click', (e) => {
    e.preventDefault();
    closeModal('loginModal');
    setTimeout(() => openModal('registerModal'), 300);
  });

  document.getElementById('switchToLoginBtn').addEventListener('click', (e) => {
    e.preventDefault();
    closeModal('registerModal');
    setTimeout(() => openModal('loginModal'), 300);
  });

  // ---- ENVÍO DE FORMULARIOS ----
  document.getElementById('loginForm').addEventListener('submit', handleLoginSubmit);
  document.getElementById('registerForm').addEventListener('submit', handleRegisterSubmit);
  document.getElementById('contactForm').addEventListener('submit', handleContactSubmit);
  document.getElementById('postForm').addEventListener('submit', handlePostSubmit);
  document.getElementById('adminAddEventForm').addEventListener('submit', handleAdminAddEvent);
  document.getElementById('adminAddOtherEventForm').addEventListener('submit', handleAdminAddOtherEvent);

  // ---- CARRUSEL ----
  inicializarCarrusel();

  // ---- EVENTOS ----
  renderEvents();
  renderOtherEventsSection();
  renderPosts();
});
