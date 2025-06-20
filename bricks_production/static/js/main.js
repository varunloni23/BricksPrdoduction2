// Main JavaScript for customer side

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Quantity input handlers
    const quantityInputs = document.querySelectorAll('.quantity-input');
    if (quantityInputs) {
        quantityInputs.forEach(input => {
            const minusBtn = input.previousElementSibling;
            const plusBtn = input.nextElementSibling;
            
            if (minusBtn && minusBtn.classList.contains('quantity-minus')) {
                minusBtn.addEventListener('click', function() {
                    let value = parseInt(input.value);
                    if (value > 1) {
                        input.value = value - 1;
                    }
                });
            }
            
            if (plusBtn && plusBtn.classList.contains('quantity-plus')) {
                plusBtn.addEventListener('click', function() {
                    let value = parseInt(input.value);
                    input.value = value + 1;
                });
            }
        });
    }

    // Product image gallery
    const mainImage = document.querySelector('.product-main-image');
    const thumbnails = document.querySelectorAll('.product-thumbnail');
    
    if (mainImage && thumbnails.length > 0) {
        thumbnails.forEach(thumb => {
            thumb.addEventListener('click', function() {
                const imgSrc = this.getAttribute('data-src');
                mainImage.src = imgSrc;
                
                // Remove active class from all thumbnails
                thumbnails.forEach(t => t.classList.remove('active'));
                
                // Add active class to clicked thumbnail
                this.classList.add('active');
            });
        });
    }

    // Stripe payment integration
    const stripeForm = document.getElementById('payment-form');
    
    if (stripeForm) {
        const stripe = Stripe(stripeForm.getAttribute('data-stripe-key'));
        const elements = stripe.elements();
        
        // Create card element
        const card = elements.create('card', {
            style: {
                base: {
                    color: '#32325d',
                    fontFamily: '"Poppins", sans-serif',
                    fontSmoothing: 'antialiased',
                    fontSize: '16px',
                    '::placeholder': {
                        color: '#aab7c4'
                    }
                },
                invalid: {
                    color: '#fa755a',
                    iconColor: '#fa755a'
                }
            }
        });
        
        // Mount the card element
        card.mount('#card-element');
        
        // Handle validation errors
        card.addEventListener('change', function(event) {
            const displayError = document.getElementById('card-errors');
            if (event.error) {
                displayError.textContent = event.error.message;
            } else {
                displayError.textContent = '';
            }
        });
        
        // Handle form submission
        stripeForm.addEventListener('submit', async function(event) {
            event.preventDefault();
            
            const submitBtn = document.getElementById('submit-payment');
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
            
            const totalAmount = parseFloat(stripeForm.getAttribute('data-amount'));
            
            try {
                // Create payment intent on the server
                const response = await fetch('/create-payment-intent', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ amount: totalAmount })
                });
                
                const data = await response.json();
                
                if (data.error) {
                    const errorElement = document.getElementById('card-errors');
                    errorElement.textContent = data.error;
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = 'Pay Now';
                    return;
                }
                
                // Confirm the payment
                const { error } = await stripe.confirmCardPayment(data.clientSecret, {
                    payment_method: {
                        card: card,
                        billing_details: {
                            name: document.getElementById('name').value
                        }
                    }
                });
                
                if (error) {
                    const errorElement = document.getElementById('card-errors');
                    errorElement.textContent = error.message;
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = 'Pay Now';
                } else {
                    // Payment succeeded, redirect to success page
                    window.location.href = '/payment-success';
                }
            } catch (err) {
                console.error('Error:', err);
                const errorElement = document.getElementById('card-errors');
                errorElement.textContent = 'An unexpected error occurred. Please try again.';
                submitBtn.disabled = false;
                submitBtn.innerHTML = 'Pay Now';
            }
        });
    }

    // Animate elements on scroll
    const animateElements = document.querySelectorAll('.fade-in');
    
    if (animateElements.length > 0) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, { threshold: 0.1 });
        
        animateElements.forEach(element => {
            element.style.opacity = '0';
            element.style.transform = 'translateY(20px)';
            element.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            observer.observe(element);
        });
    }
}); 