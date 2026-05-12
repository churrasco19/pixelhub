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
  const passwordHash = await hashPassword(formData.password);
  const nuevoUsuario = {
    id: Date.now(), // ID simple basado en timestamp
    nombre: escapeHtml(formData.nombre),
    email: normalizedEmail,
    passwordHash: passwordHash,
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
  '../imagenes/pixelhub.png',
  '../imagenes/pixelhubNoche.jpeg',
  '../imagenes/logo.png'
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
const events = [
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

  if (sessionUser) {
    // Usuario logueado
    loginBtn.style.display = 'none';
    registerBtn.style.display = 'none';
    userGreeting.style.display = 'flex';
    userNameDisplay.textContent = `Hola, ${escapeHtml(sessionUser.nombre)}`;
  } else {
    // Usuario NO logueado
    loginBtn.style.display = 'block';
    registerBtn.style.display = 'block';
    userGreeting.style.display = 'none';
  }

  // Re-renderizar eventos y resumen de registro
  userInscriptions = loadInscriptions();
  renderEvents();
  renderRegistrationSummary();
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

  // Simular envío (en producción, hacer POST a servidor)
  mostrarToast('¡Mensaje enviado! Nos pondremos en contacto pronto. 📧');
  document.getElementById('contactForm').reset();
  document.getElementById('contactSuccess').style.display = 'block';
  document.getElementById('contactSuccess').textContent =
    'Gracias por tu mensaje. Responderemos pronto.';

  // Ocultar mensaje después de 4 segundos
  setTimeout(() => {
    document.getElementById('contactSuccess').style.display = 'none';
  }, 4000);
}

// ============================================================================
// INICIALIZACIÓN (DOMContentLoaded)
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
  // Actualizar estado de autenticación al cargar
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

  // ---- CERRAR MODALES ----
  document.getElementById('closeLoginBtn').addEventListener('click', () => {
    closeModal('loginModal');
  });

  document.getElementById('closeRegisterBtn').addEventListener('click', () => {
    closeModal('registerModal');
  });

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

  // ---- CARRUSEL ----
  inicializarCarrusel();

  // ---- EVENTOS ----
  renderEvents();
});
