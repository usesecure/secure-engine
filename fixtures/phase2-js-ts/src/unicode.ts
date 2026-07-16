export function saludo(nombre: string) {
  const mensaje = `Hola, ${nombre} 👋`;
  return {
    café: mensaje,
    ubicación: process.env.REGIÓN,
  };
}
