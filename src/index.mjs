import implicitRenderHtml from './implicit.html';

async function handlePost(request) {
    let res = await fetch(request)
    const body = await request.formData();

    // Turnstile injects a token in "cf-turnstile-response".
    const token = body.get('cf-turnstile-response');
    const ip = request.headers.get('CF-Connecting-IP');

    // Validate the token by calling the "/siteverify" API.
    let formData = new FormData();
    formData.append('secret', secret_key);
    formData.append('response', token);
    formData.append('remoteip', ip);

    const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        body: formData,
        method: 'POST',
    });

    const outcome = await result.json();
    if (!outcome.success) {
        return new Response('The provided Turnstile token was not valid!', { status: 401 });
    }
    return res
}

export default {
    async fetch(request) {
        let body = implicitRenderHtml
        let newResponse = await fetch(request)

        if (newResponse.method === 'POST') {
            return await handlePost(request);
        }

        let response = new Response(body, newResponse.body)
        //     if ( response.headers.get('Host') === 'challenge.cloudflare.com' &&
        //     response.method === 'POST' && response.status === 200) {
        //         return await handlePost(request) 
        //     }

        response.headers.set("cf-edge-cache", "no-cache")
        response.headers.set("content-type", "text/html;charset=UTF-8")
        return response
    },
};


// export default {
//     async fetch(request) {
//         if (
//             request.headers.get('Host') === 'challenge.cloudflare.com' &&
//             request.method === 'POST') {
            
//             const response = await fetch(request)

//             if (response.status === 200) {
//                 return await handlePost(request)
//             }
//             return response
//         }

//         let body = implicitRenderHtml;

//         return new Response(body, {
//             headers: {
//                 'Content-Type': 'text/html',
//             },
//         });
//     },
// };