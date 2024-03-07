import { getClientIP } from './utils.js'

export async function verifyChallenge(request, env) {
  const body = await request.formData();
  const token = body.get('cf-turnstile-response');
  const ip = await getClientIP(request);
  const originalUrl = body.get('originalUrl')

  // Validate the token by calling the "/siteverify" API.
  let formData = new FormData();
  formData.append('secret', env.SECRET_KEY);
  formData.append('response', token);
  formData.append('remoteip', ip);


  const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    body: formData,
    method: 'POST',
  });

  const outcome = await result.json();
  console.log(JSON.stringify(outcome)); // This will log the full response body as a string
  if (!outcome.success) {
    // Handle verification failure
    return new Response('The provided Turnstile token was not valid!', { status: 401 });
  }

  // Redirect the user to the decoded original URL upon successful verification
  return Response.redirect(originalUrl, 302);
}