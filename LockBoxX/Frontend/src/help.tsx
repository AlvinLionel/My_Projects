import "../styles/help.css";

interface HelpProps {
    onBack: () => void;
}

function Help({ onBack }: HelpProps) {
    return (
        <div className="help-page">
            <header className="help-navbar">
                <div className="help-brand">
                    <div className="help-brand-icon">◈</div>
                    <div className="help-brand-copy">
                        <h1>LockBoxX</h1>
                        <span>HELP &amp; GUIDE</span>
                    </div>
                </div>
                <button type="button" className="help-back" onClick={onBack}>
                    ← Back to LockBoxX
                </button>
            </header>

            <main className="help-main">
                <section className="help-hero">
                    <div className="help-eyebrow">
                        <span className="help-eyebrow-line" />
                        LOCKBOXX DOCUMENTATION
                    </div>
                    <h2>How can we help?</h2>
                    <p>Learn how to navigate LockBoxX, protect your resources,and understand the security tools available to you.</p>
                </section>

                <section className="help-overview">
                    <div className="help-section-heading">
                        <span className="help-section-label">START HERE</span>
                        <h3>Your security workspace</h3>
                    </div>

                    <div className="help-section-copy">
                        <p>LockBoxX is a browser-based security workspace designed to make protecting digital resources straightforward.</p>
                        <p> Choose what you want to protect, select an appropriate security method, provide the required credentials, and let LockBoxX handle the cryptographic operation.</p>
                    </div>
                </section>

                {/* WORKSPACE */}
                <section className="help-section">
                    <div className="help-section-intro">
                        <span className="help-section-label"> 01 · WORKSPACE</span>

                        <h3>Understanding the LockBoxX workspace</h3>
                        <p>The main workspace is where you perform encryption, decryption, locking, and unlocking operations. The interface is organized around the resource you want to protect and the security method you want to use.</p>
                    </div>

                    <figure className="help-image">
                        <div className="help-image-label">
                            WORKSPACE OVERVIEW
                        </div>
                        <div className="help-image-frame">
                            <img src="/help/workspace-overview.webp" alt="LockBoxX workspace overview" />
                        </div>
                        <figcaption>
                            The LockBoxX workspace is where you select the security operation you want to perform.
                        </figcaption>
                    </figure>
                </section>

                {/* GETTING STARTED */}
                <section className="help-section">
                    <div className="help-section-intro">
                        <span className="help-section-label">02 · GETTING STARTED</span>
                        <h3> Protecting your first resource</h3>
                        <p>Most operations in LockBoxX follow the same basicsequence. You choose a resource, select how it should be protected, provide the required credentials, and start the operation.</p>
                    </div>

                    <div className="help-steps">
                        <article className="help-step">
                            <span className="help-step-number">01</span>
                            <div>
                                <h4>Choose a resource</h4>
                                <p>Select the type of resource you want to protect. Depending on the selected resource, LockBoxX will present the security methods that are appropriate for it.</p>
                            </div>
                        </article>
                        <article className="help-step">
                            <span className="help-step-number">02</span>
                            <div>
                                <h4>Select a security method</h4>
                                <p>Choose an available encryption or protection method. The available options depend on the resource and operation you selected.</p>
                            </div>
                        </article>
                        <article className="help-step">
                            <span className="help-step-number">03</span>
                            <div>
                                <h4>Provide your credentials</h4>
                                <p>Enter the password or other required key material. Keep your credentials secure because LockBoxX cannot recover a forgotten password for you.</p>
                            </div>
                        </article>
                        <article className="help-step">
                            <span className="help-step-number">04</span>
                            <div>
                                <h4>Start the operation</h4>
                                <p>Begin the protection process and wait for LockBoxX to complete the operation. Progress and the final result are shown directly in the workspace.</p>
                            </div>
                        </article>
                    </div>
                </section>

                {/* RESOURCES */}
                <section className="help-section">
                    <div className="help-section-intro">
                        <span className="help-section-label">03 · RESOURCES</span>
                        <h3>What can you protect?</h3>
                        <p>LockBoxX organizes its workspace around the type of resource you are working with. Selecting a resource helps determine which protection methods are available.</p>
                    </div>

                    <div className="help-resource-grid">
                        <article className="help-resource">
                            <span className="help-resource-icon">T</span>
                            <div>
                                <h4>Text</h4>
                                <p>Protect text directly within the LockBoxX workspace.</p>
                            </div>
                        </article>
                        <article className="help-resource">
                            <span className="help-resource-icon">F</span>
                            <div>
                                <h4>Files</h4>
                                <p>Protect supported files while preserving their original content.</p>
                            </div>
                        </article>
                        <article className="help-resource">
                            <span className="help-resource-icon">I</span>
                            <div>
                                <h4>Images</h4>
                                <p>Protect image resources using the available security methods.</p>
                            </div>
                        </article>
                        <article className="help-resource">
                            <span className="help-resource-icon">A</span>
                            <div>
                                <h4>Audio</h4>
                                <p>Protect supported audio resources through the workspace.</p>
                            </div>
                        </article>
                        <article className="help-resource">
                            <span className="help-resource-icon">V</span>
                            <div>
                                <h4>Video</h4>
                                <p>Protect supported video resources with the available methods.</p>
                            </div>
                        </article>
                        <article className="help-resource">
                            <span className="help-resource-icon">+</span>
                            <div>
                                <h4>More resources</h4>
                                <p>Available resource types may depend on the protection method and LockBoxX capabilities.</p>
                            </div>
                        </article>
                    </div>

                    <figure className="help-image">
                        <div className="help-image-label">
                            RESOURCE SELECTION
                        </div>
                        <div className="help-image-frame">
                            <img src="/help/resource-selection.webp" alt="LockBoxX resource selection" />
                        </div>

                        <figcaption>
                            Select the type of resource you want to protect. Available options vary on the operation being run and automatically determine which security methods can be used.
                        </figcaption>
                    </figure>
                </section>

                {/* SECURITY METHODS */}
                <section className="help-section">
                    <div className="help-section-intro">
                        <span className="help-section-label">04 · SECURITY METHODS</span>
                        <h3>Choosing a protection method</h3>
                        <p>Security methods determine how your resource is protected. LockBoxX presents methods based on the resource and operation you are performing.</p>
                    </div>
                    <div className="help-method-grid">
                        <article className="help-method">
                            <div className="help-method-top">
                                <span>01</span>
                                <strong>Encryption</strong>
                            </div>
                            <p>Cryptographically transform your resource so that its original contents cannot be understood without the required credentials. Requires manual picking of encryption algorithm.</p>
                        </article>
                        <article className="help-method">
                            <div className="help-method-top">
                                <span>02</span>
                                <strong>Password protection</strong>
                            </div>
                            <p>Apply password-based protection where the resource format supports native protection.</p>
                        </article>
                    </div>
                    <figure className="help-image">
                        <div className="help-image-label">
                            SECURITY METHODS
                        </div>
                        <div className="help-image-frame">
                            <img src="/help/security-methods.webp" alt="LockBoxX security method selection" />
                        </div>
                        <figcaption>
                            Security methods available in LockBoxX depend on the selected resource and the type of operation being performed.
                        </figcaption>
                    </figure>
                </section>

                {/* PROTECTION WORKFLOW */}
                <section className="help-section">
                    <div className="help-section-intro">
                        <span className="help-section-label">05 · PROTECTION</span>
                        <h3>Protecting a resource</h3>
                        <p>Once your resource and security method have been selected, LockBoxX guides you through the protection process.</p>
                    </div>
                    <div className="help-flow">
                        <div className="help-flow-item">
                            <span>01</span>
                            <strong>Select</strong>
                            <p>Choose the resource you want to protect.</p>
                        </div>
                        <div className="help-flow-line" />
                        <div className="help-flow-item">
                            <span>02</span>
                            <strong>Configure</strong>
                            <p>Select the available security method and provide the required credentials.</p>
                        </div>
                        <div className="help-flow-line" />
                        <div className="help-flow-item">
                            <span>03</span>
                            <strong>Protect</strong>
                            <p>Start the operation and allow LockBoxX to process the resource.</p>
                        </div>
                        <div className="help-flow-line" />
                        <div className="help-flow-item">
                            <span>04</span>
                            <strong>Save</strong>
                            <p>Download or otherwise retain the resulting protected resource.</p>
                        </div>
                    </div>

                    <figure className="help-image">
                        <div className="help-image-label">
                            PROTECTION WORKFLOW
                        </div>
                        <div className="help-image-frame">
                            <img src="/help/protection-workflow.webp" alt="LockBoxX protection workflow" />
                        </div>
                        <figcaption>
                            Configure the selected resource, select the encryption algorithm then enter your credentials.
                        </figcaption>
                    </figure>
                </section>

                {/* UNLOCKING */}
                <section className="help-section">
                    <div className="help-section-intro">
                        <span className="help-section-label">06 · UNLOCKING</span>
                        <h3>Unlocking a protected resource</h3>
                        <p>Protected resources can be processed through the appropriate unlocking or decryption workflow. The credentials used during protection are required to recover the original resource.</p>
                    </div>
                    <div className="help-notice">
                        <span className="help-notice-icon">!</span>
                        <div>
                            <strong>Keep your password safe</strong>
                            <p>LockBoxX does not provide a way to bypass cryptographic protection when the required password or key is unavailable.</p>
                        </div>
                    </div>
                    <figure className="help-image">
                        <div className="help-image-label">
                            UNLOCKING WORKFLOW
                        </div>
                        <div className="help-image-frame">
                            <img src="/help/unlocking-workflow.webp" alt="LockBoxX unlocking workflow" />
                        </div>
                        <figcaption>
                            Use the appropriate credentials and unlocking operation to recover a protected resource.
                        </figcaption>
                    </figure>
                </section>

                {/* RESULTS */}
                <section className="help-section">
                    <div className="help-section-intro">
                        <span className="help-section-label">07 · RESULTS</span>
                        <h3>Understanding your results</h3>
                        <p>After an operation completes, LockBoxX presents the result in the workspace. Depending on the operation, you may be able to copy, download, or continue working with the resulting resource.</p>
                    </div>
                    <div className="help-result-list">
                        <div className="help-result-item">
                            <span className="help-result-status">01</span>
                            <div>
                                <strong>Operation complete</strong>
                                <p>Indicates that the requested operation finished successfully.</p>
                            </div>
                        </div>
                        <div className="help-result-item">
                            <span className="help-result-status">02</span>
                            <div>
                                <strong>Result available</strong>
                                <p>The processed resource or resulting content is presented for the next step.</p>
                            </div>
                        </div>
                        <div className="help-result-item">
                            <span className="help-result-status">03</span>
                            <div>
                                <strong>Download</strong>
                                <p>Save the resulting protected orrecovered resource to your device.</p>
                            </div>
                        </div>
                    </div>
                    <figure className="help-image">
                        <div className="help-image-label">
                            OPERATION RESULTS
                        </div>
                        <div className="help-image-frame">
                            <img src="/help/results.webp" alt="LockBoxX operation results" />
                        </div>
                        <figcaption>
                            Review the completed operation and use the available controls to
                            copy, download, or continue working with the resulting resource.
                        </figcaption>
                    </figure>
                </section>

                {/* PASSWORDS */}
                <section className="help-section help-section-compact">
                    <div className="help-section-intro">
                        <span className="help-section-label">
                            08 · SECURITY
                        </span>
                        <h3>Passwords &amp; security</h3>
                        <p>Your password is an important part of protecting your resources. Use strong, unique passwords and avoid sharing them with other people.</p>
                    </div>
                    <div className="help-security-points">
                        <div>
                            <strong>Use strong passwords</strong>
                            <p>Prefer passwords that are long, unique, and difficult to guess.</p>
                        </div>
                        <div>
                            <strong>Do not reuse important passwords</strong>
                            <p>A password protecting sensitive resources should not be reused elsewhere.</p>
                        </div>
                        <div>
                            <strong>Keep backups of important resources</strong>
                            <p>Protection does not replace having reliable backups of information you cannot afford to lose.</p>
                        </div>
                        <div>
                            <strong>Never lose your credentials</strong>
                            <p>Strong cryptographic protection also means that forgotten credentials may make the protected resource unrecoverable. </p>
                        </div>
                    </div>
                </section>

                {/* TROUBLESHOOTING */}
                <section className="help-section">
                    <div className="help-section-intro">
                        <span className="help-section-label">
                            09 · TROUBLESHOOTING
                        </span>
                        <h3> When something goes wrong</h3>
                        <p>If an operation fails, start by checking the resource, credentials, selected method, and whether the resource is supported by that method.</p>
                    </div>

                    <div className="help-troubleshooting">
                        <div className="help-trouble">
                            <strong>The operation cannot start</strong>
                            <p> Check that a resource has been selected and that all required fields have been completed.</p>
                        </div>
                        <div className="help-trouble">
                            <strong>The password is rejected</strong>
                            <p>Verify that you entered the same credentials used when the resource was protected.</p>
                        </div>
                        <div className="help-trouble">
                            <strong>The resource cannot be processed</strong>
                            <p>Confirm that the resource type is supported by the selected operation and security method.</p>
                        </div>
                        <div className="help-trouble">
                            <strong>The resulting file cannot be opened</strong>
                            <p>Make sure the operation completed successfully and that the resulting file was not modified or corrupted after being created.</p>
                        </div>
                    </div>
                </section>

                {/* FAQ */}
                <section className="help-section help-faq">
                    <div className="help-section-intro">
                        <span className="help-section-label">
                            10 · FAQ
                        </span>
                        <h3>Frequently asked questions</h3>
                    </div>
                    <div className="help-faq-list">
                        <details>
                            <summary>What is LockBoxX?</summary>
                            <p>LockBoxX is a fully client-side based security workspace for protecting and recovering supported digital resources using cryptographic and supported native protection methods.</p>
                        </details>
                        <details>
                            <summary>Does LockBoxX store my password?</summary>
                            <p>Your password is treated as sensitive information. The platform does not store any data as everything is erased at the end of every session.</p>
                        </details>
                        <details>
                            <summary>What happens if I forget my password?</summary>
                            <p>Cryptographic protection is designed to prevent unauthorized recovery. If the required credentials are lost, the protected resource may not be recoverable.</p>
                        </details>
                        <details>
                            <summary>Can I use LockBoxX without installing software?</summary>
                            <p>Yes. LockBoxX is designed to operate through the web interface, allowing supported security operations to be performed directly from your browser.</p>
                        </details>
                        <details>
                            <summary>Where should I report a problem?</summary>
                            <p>If you encounter an issue that is not covered by this guide, please contaxt me personally as I am yet to implement contact😂: <a href="mailto: alvinlionel053@gmail.com">My Email</a></p>
                        </details>
                    </div>
                </section>

                {/* FOOTER */}
                <footer className="help-footer">
                    <div>
                        <strong>LockBoxX</strong>
                        <span>
                            CRYPTOGRAPHIC WORKSPACE
                        </span>
                    </div>
                    <p>Protect what matters.</p>
                </footer>

            </main>
        </div>
    );
}

export default Help;